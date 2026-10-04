const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");

if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();

// ==========================================
// CONSTANTS & VALIDATIONS
// ==========================================
const ROLES = Object.freeze({
  ADMIN: "ADMIN",
  CUSTOMER: "CUSTOMER",
  WAREHOUSE: "WAREHOUSE",
  DELIVERY: "DELIVERY",
});

const ORDER_STATUS = Object.freeze({
  NEW: "NEW",
  PREPARING: "PREPARING",
  READY_FOR_DELIVERY: "READY_FOR_DELIVERY",
  ASSIGNED_TO_DELIVERY: "ASSIGNED_TO_DELIVERY",
  OUT_FOR_DELIVERY: "OUT_FOR_DELIVERY",
  DELIVERED: "DELIVERED",
  COMPLETED: "COMPLETED",
  CANCELLED: "CANCELLED",
});

const PAYMENT_METHODS = Object.freeze({
  CASH: "CASH",
  WALLET: "WALLET",
  BANK_TRANSFER: "BANK_TRANSFER",
});

const CURRENCY = "YER";

// Strict State Machine Matrix
const ALLOWED_STATUS_TRANSITIONS = Object.freeze({
  [ORDER_STATUS.NEW]: [ORDER_STATUS.PREPARING, ORDER_STATUS.CANCELLED],
  [ORDER_STATUS.PREPARING]: [ORDER_STATUS.READY_FOR_DELIVERY, ORDER_STATUS.CANCELLED],
  [ORDER_STATUS.READY_FOR_DELIVERY]: [ORDER_STATUS.ASSIGNED_TO_DELIVERY, ORDER_STATUS.CANCELLED],
  [ORDER_STATUS.ASSIGNED_TO_DELIVERY]: [ORDER_STATUS.OUT_FOR_DELIVERY, ORDER_STATUS.CANCELLED],
  [ORDER_STATUS.OUT_FOR_DELIVERY]: [ORDER_STATUS.DELIVERED, ORDER_STATUS.CANCELLED],
  [ORDER_STATUS.DELIVERED]: [ORDER_STATUS.COMPLETED],
  [ORDER_STATUS.COMPLETED]: [],
  [ORDER_STATUS.CANCELLED]: [],
});

// ==========================================
// SECURITY & NUMERIC HELPERS
// ==========================================
function isFiniteNumber(val) {
  return typeof val === "number" && Number.isFinite(val);
}

function requireNonNegativeNumber(val, fieldName) {
  if (!isFiniteNumber(val) || val < 0) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `Field '${fieldName}' must be a valid non-negative number.`
    );
  }
  return val;
}

function requireNonNegativeInteger(val, fieldName) {
  if (!Number.isInteger(val) || val < 0) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `Field '${fieldName}' must be a valid non-negative integer.`
    );
  }
  return val;
}

function validateNonEmptyString(val, fieldName) {
  if (!val || typeof val !== "string" || val.trim().length === 0) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `Field '${fieldName}' must be a non-empty string.`
    );
  }
  return val.trim();
}

async function getActiveUserData(uid) {
  if (!uid || typeof uid !== "string") {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required.");
  }

  const userSnap = await db.collection("users").doc(uid).get();
  if (!userSnap.exists) {
    throw new functions.https.HttpsError("permission-denied", "User record does not exist.");
  }

  const userData = userSnap.data();
  if (userData.disabled === true) {
    throw new functions.https.HttpsError("permission-denied", "User account is disabled.");
  }

  return userData;
}

async function requireRole(uid, allowedRoles) {
  const userData = await getActiveUserData(uid);
  const rolesArray = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

  if (!rolesArray.includes(userData.role)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "User does not have the required permissions."
    );
  }

  return userData;
}

function computeIdempotencyHash(customerId, orderKey) {
  return crypto
    .createHash("sha256")
    .update(`${customerId}_${orderKey}`)
    .digest("hex");
}

async function getFirstAdminUid() {
  const adminQuery = await db
    .collection("users")
    .where("role", "==", ROLES.ADMIN)
    .get();

  if (adminQuery.empty) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "No active admin account found in the system."
    );
  }

  for (const doc of adminQuery.docs) {
    const data = doc.data();
    if (data && data.disabled !== true) {
      return doc.id;
    }
  }

  throw new functions.https.HttpsError(
    "failed-precondition",
    "No active admin account found in the system."
  );
}

// ==========================================
// 1. submitCustomerOrderSecure
// ==========================================
exports.submitCustomerOrderSecure = functions.https.onCall(
  async (data, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Authentication required.");
    }

    const customerUid = context.auth.uid;
    await requireRole(customerUid, ROLES.CUSTOMER);

    const orderKey = validateNonEmptyString(data.orderKey, "orderKey");
    const deliveryAddress = validateNonEmptyString(data.deliveryAddress, "deliveryAddress");
    const notes = typeof data.notes === "string" ? data.notes.trim() : "";

    let paymentMethod = null;
    if (data.paymentMethod && typeof data.paymentMethod === "string" && data.paymentMethod.trim().length > 0) {
      const pmInput = data.paymentMethod.trim().toUpperCase();
      if (!Object.values(PAYMENT_METHODS).includes(pmInput)) {
        throw new functions.https.HttpsError("invalid-argument", "Invalid payment method provided.");
      }
      paymentMethod = pmInput;
    }

    if (!Array.isArray(data.cart) || data.cart.length === 0) {
      throw new functions.https.HttpsError("invalid-argument", "Cart must be a non-empty array.");
    }

    const itemMap = new Map();
    for (const item of data.cart) {
      const pId = validateNonEmptyString(item.productId, "cart.productId");
      const qty = requireNonNegativeInteger(item.quantity, "cart.quantity");

      if (qty === 0 || qty > 1000000) {
        throw new functions.https.HttpsError("invalid-argument", `Invalid quantity for product ${pId}.`);
      }
      itemMap.set(pId, (itemMap.get(pId) || 0) + qty);
    }

    const adminUid = await getFirstAdminUid();
    const idempotencyHash = computeIdempotencyHash(customerUid, orderKey);
    const idempotencyRef = db.collection("idempotencyKeys").doc(idempotencyHash);

    return await db.runTransaction(async (transaction) => {
      // Step A: Idempotency check
      const idempotencyDoc = await transaction.get(idempotencyRef);
      if (idempotencyDoc.exists) {
        return {
          duplicate: true,
          orderId: idempotencyDoc.data().orderId,
          message: "Order already processed with this orderKey.",
        };
      }

      // Step B: Read all product documents
      const productRefs = Array.from(itemMap.keys()).map((id) =>
        db.collection("products").doc(id)
      );
      const productDocs = await Promise.all(
        productRefs.map((ref) => transaction.get(ref))
      );

      // Step C: Validate product status and stock
      const orderItems = [];
      let totalAmount = 0;

      for (let i = 0; i < productDocs.length; i++) {
        const docSnap = productDocs[i];
        const pId = docSnap.id;
        const requestedQty = itemMap.get(pId);

        if (!docSnap.exists) {
          throw new functions.https.HttpsError("not-found", `Product ${pId} not found.`);
        }

        const pData = docSnap.data();
        if (pData.status !== "ACTIVE") {
          throw new functions.https.HttpsError(
            "failed-precondition",
            `Product ${pData.name || pId} is not ACTIVE.`
          );
        }

        if (!isFiniteNumber(pData.sellingPrice) || pData.sellingPrice < 0) {
          throw new functions.https.HttpsError(
            "failed-precondition",
            `Product ${pId} has an invalid sellingPrice on the server.`
          );
        }

        const quantity = requireNonNegativeInteger(pData.quantity, `products.${pId}.quantity`);
        const reservedQuantity = requireNonNegativeInteger(pData.reservedQuantity, `products.${pId}.reservedQuantity`);

        if (quantity < reservedQuantity) {
          throw new functions.https.HttpsError(
            "failed-precondition",
            `Inconsistent inventory state for product ${pId}.`
          );
        }

        const availableQuantity = quantity - reservedQuantity;
        if (availableQuantity < requestedQty) {
          throw new functions.https.HttpsError(
            "failed-precondition",
            `Insufficient stock for product ${pData.name || pId}. Available: ${availableQuantity}, Requested: ${requestedQty}.`
          );
        }

        const unitPrice = pData.sellingPrice;
        const discount = isFiniteNumber(pData.discount) && pData.discount >= 0 ? pData.discount : 0;
        const finalPrice = Math.max(0, unitPrice - discount);
        const subtotal = finalPrice * requestedQty;
        totalAmount += subtotal;

        orderItems.push({
          productId: pId,
          productName: pData.name || "",
          requestedQuantity: requestedQty,
          unitPrice,
          discount,
          finalPrice,
          subtotal,
          ref: docSnap.ref,
          currentReserved: reservedQuantity,
        });
      }

      // Step D: Write Operations
      for (const item of orderItems) {
        transaction.update(item.ref, {
          reservedQuantity: item.currentReserved + item.requestedQuantity,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }

      const newOrderRef = db.collection("orders").doc();
      const orderPayload = {
        orderId: newOrderRef.id,
        customerId: customerUid,
        orderKey,
        deliveryAddress,
        notes,
        paymentMethod,
        paymentStatus: "UNPAID",
        items: orderItems.map((i) => ({
          productId: i.productId,
          productName: i.productName,
          quantity: i.requestedQuantity,
          unitPrice: i.unitPrice,
          discount: i.discount,
          finalPrice: i.finalPrice,
          subtotal: i.subtotal,
        })),
        totalAmount,
        status: ORDER_STATUS.NEW,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };
      transaction.set(newOrderRef, orderPayload);

      transaction.set(idempotencyRef, {
        orderId: newOrderRef.id,
        customerId: customerUid,
        orderKey,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      const notifRef = db.collection("notifications").doc();
      transaction.set(notifRef, {
        notificationId: notifRef.id,
        userId: adminUid,
        title: "New Order Received",
        body: `New order ${newOrderRef.id} placed by customer.`,
        type: "NEW_ORDER",
        read: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      return {
        duplicate: false,
        orderId: newOrderRef.id,
        totalAmount,
        status: ORDER_STATUS.NEW,
      };
    });
  }
);

// ==========================================
// 2. cancelOrder
// ==========================================
exports.cancelOrder = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required.");
  }

  const orderId = validateNonEmptyString(data.orderId, "orderId");
  const callerUid = context.auth.uid;
  const callerUserData = await getActiveUserData(callerUid);
  const callerRole = callerUserData.role;

  // Strict Role Allowlist Validation (DELIVERY is explicitly excluded)
  const allowedCancelRoles = [ROLES.ADMIN, ROLES.CUSTOMER, ROLES.WAREHOUSE];
  if (!allowedCancelRoles.includes(callerRole)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "User role is not authorized to cancel orders."
    );
  }

  return await db.runTransaction(async (transaction) => {
    const orderRef = db.collection("orders").doc(orderId);
    const orderSnap = await transaction.get(orderRef);

    if (!orderSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Order not found.");
    }

    const orderData = orderSnap.data();

    // CUSTOMER ownership & state check
    if (callerRole === ROLES.CUSTOMER) {
      if (orderData.customerId !== callerUid) {
        throw new functions.https.HttpsError("permission-denied", "Cannot cancel another customer's order.");
      }
      if (orderData.status === ORDER_STATUS.OUT_FOR_DELIVERY) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          "Customer cannot cancel an order that is already out for delivery."
        );
      }
    }

    // WAREHOUSE stage restriction
    if (callerRole === ROLES.WAREHOUSE) {
      const warehouseAllowed = [ORDER_STATUS.NEW, ORDER_STATUS.PREPARING, ORDER_STATUS.READY_FOR_DELIVERY];
      if (!warehouseAllowed.includes(orderData.status)) {
        throw new functions.https.HttpsError("permission-denied", "Warehouse cannot cancel order at this stage.");
      }
    }

    // ADMIN stage restriction
    if (callerRole === ROLES.ADMIN) {
      const adminAllowed = [ORDER_STATUS.NEW, ORDER_STATUS.PREPARING, ORDER_STATUS.READY_FOR_DELIVERY, ORDER_STATUS.ASSIGNED_TO_DELIVERY];
      if (!adminAllowed.includes(orderData.status)) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          `Admin cannot cancel order in status '${orderData.status}'.`
        );
      }
    }

    // Explicit Universal Guard: Block cancellation of OUT_FOR_DELIVERY, DELIVERED, COMPLETED, CANCELLED
    if (
      orderData.status === ORDER_STATUS.OUT_FOR_DELIVERY ||
      orderData.status === ORDER_STATUS.DELIVERED ||
      orderData.status === ORDER_STATUS.COMPLETED ||
      orderData.status === ORDER_STATUS.CANCELLED
    ) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        `Order in status '${orderData.status}' cannot be cancelled.`
      );
    }

    const allowedTransitions = ALLOWED_STATUS_TRANSITIONS[orderData.status] || [];
    if (!allowedTransitions.includes(ORDER_STATUS.CANCELLED)) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        `Order in status '${orderData.status}' cannot be cancelled.`
      );
    }

    const items = orderData.items || [];
    const productRefs = items.map((i) => db.collection("products").doc(i.productId));
    const productDocs = await Promise.all(productRefs.map((ref) => transaction.get(ref)));

    const productUpdates = [];
    for (let i = 0; i < productDocs.length; i++) {
      const pSnap = productDocs[i];
      const item = items[i];

      if (!pSnap.exists) {
        throw new functions.https.HttpsError("not-found", `Product ${item.productId} not found.`);
      }

      const pData = pSnap.data();
      const currentReserved = requireNonNegativeInteger(pData.reservedQuantity, `products.${pSnap.id}.reservedQuantity`);
      const orderedQty = requireNonNegativeInteger(item.quantity, "item.quantity");

      if (currentReserved < orderedQty) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          `Cannot release reserved stock for ${pSnap.id}. Current reserved (${currentReserved}) is less than order quantity (${orderedQty}).`
        );
      }

      productUpdates.push({
        ref: pSnap.ref,
        newReserved: currentReserved - orderedQty,
      });
    }

    for (const update of productUpdates) {
      transaction.update(update.ref, {
        reservedQuantity: update.newReserved,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    transaction.update(orderRef, {
      status: ORDER_STATUS.CANCELLED,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const notifRef = db.collection("notifications").doc();
    transaction.set(notifRef, {
      notificationId: notifRef.id,
      userId: orderData.customerId,
      title: "Order Cancelled",
      body: `Your order ${orderId} has been cancelled.`,
      type: "ORDER_CANCELLED",
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { success: true, orderId, status: ORDER_STATUS.CANCELLED };
  });
});

// ==========================================
// 3. fulfillOrderSecure
// ==========================================
exports.fulfillOrderSecure = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required.");
  }

  const orderId = validateNonEmptyString(data.orderId, "orderId");
  const callerUid = context.auth.uid;
  await requireRole(callerUid, ROLES.DELIVERY);

  const paymentMethodInput = validateNonEmptyString(data.paymentMethod, "paymentMethod").toUpperCase();
  if (!Object.values(PAYMENT_METHODS).includes(paymentMethodInput)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid payment method provided at delivery.");
  }

  const paymentReferenceInput = data.paymentReference
    ? String(data.paymentReference).trim()
    : "";

  if (
    (paymentMethodInput === PAYMENT_METHODS.WALLET || paymentMethodInput === PAYMENT_METHODS.BANK_TRANSFER) &&
    !paymentReferenceInput
  ) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      `paymentReference is required for payment method ${paymentMethodInput}.`
    );
  }

  return await db.runTransaction(async (transaction) => {
    const orderRef = db.collection("orders").doc(orderId);
    const orderSnap = await transaction.get(orderRef);

    if (!orderSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Order not found.");
    }

    const orderData = orderSnap.data();

    if (orderData.status !== ORDER_STATUS.OUT_FOR_DELIVERY) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        `Order must be in '${ORDER_STATUS.OUT_FOR_DELIVERY}' status to be fulfilled.`
      );
    }

    if (orderData.deliveryAgentId !== callerUid) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "Order is assigned to a different delivery agent."
      );
    }

    const items = orderData.items || [];
    const productRefs = items.map((i) => db.collection("products").doc(i.productId));
    const productDocs = await Promise.all(productRefs.map((ref) => transaction.get(ref)));

    const productUpdates = [];
    const inventoryLogs = [];

    for (let i = 0; i < productDocs.length; i++) {
      const pSnap = productDocs[i];
      const item = items[i];

      if (!pSnap.exists) {
        throw new functions.https.HttpsError("not-found", `Product ${item.productId} not found.`);
      }

      const pData = pSnap.data();
      const currentQty = requireNonNegativeInteger(pData.quantity, `products.${pSnap.id}.quantity`);
      const currentReserved = requireNonNegativeInteger(pData.reservedQuantity, `products.${pSnap.id}.reservedQuantity`);
      const orderedQty = requireNonNegativeInteger(item.quantity, "item.quantity");

      if (currentQty < orderedQty || currentReserved < orderedQty) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          `Insufficient stock/reserved stock for product ${pSnap.id}. Quantity: ${currentQty}, Reserved: ${currentReserved}, Requested: ${orderedQty}.`
        );
      }

      const newQty = currentQty - orderedQty;
      const newReserved = currentReserved - orderedQty;

      if (newQty < 0 || newReserved < 0) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          `Inventory levels cannot become negative for product ${pSnap.id}.`
        );
      }

      productUpdates.push({
        ref: pSnap.ref,
        newQty,
        newReserved,
      });

      inventoryLogs.push({
        productId: item.productId,
        orderId,
        changeType: "FULFILLMENT",
        quantityDeducted: orderedQty,
        previousQuantity: currentQty,
        newQuantity: newQty,
        previousReserved: currentReserved,
        newReserved,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    for (const pUpd of productUpdates) {
      transaction.update(pUpd.ref, {
        quantity: pUpd.newQty,
        reservedQuantity: pUpd.newReserved,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    for (const log of inventoryLogs) {
      const logRef = db.collection("inventoryLogs").doc();
      transaction.set(logRef, log);
    }

    const officialAmount = requireNonNegativeNumber(orderData.totalAmount, "orders.totalAmount");

    const invoiceRef = db.collection("invoices").doc();
    transaction.set(invoiceRef, {
      invoiceId: invoiceRef.id,
      orderId,
      customerId: orderData.customerId,
      totalAmount: officialAmount,
      currency: CURRENCY,
      status: "PAID",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const paymentRef = db.collection("payments").doc();
    transaction.set(paymentRef, {
      paymentId: paymentRef.id,
      orderId,
      customerId: orderData.customerId,
      amount: officialAmount,
      currency: CURRENCY,
      method: paymentMethodInput,
      paymentReference: paymentReferenceInput || null,
      status: "COMPLETED",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    transaction.update(orderRef, {
      status: ORDER_STATUS.DELIVERED,
      paymentMethod: paymentMethodInput,
      paymentStatus: "PAID",
      amountCollected: officialAmount,
      deliveredAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const notifRef = db.collection("notifications").doc();
    transaction.set(notifRef, {
      notificationId: notifRef.id,
      userId: orderData.customerId,
      title: "Order Delivered",
      body: `Your order ${orderId} has been successfully delivered.`,
      type: "ORDER_DELIVERED",
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      success: true,
      orderId,
      status: ORDER_STATUS.DELIVERED,
      invoiceId: invoiceRef.id,
      paymentId: paymentRef.id,
    };
  });
});

// ==========================================
// 4. assignDeliveryAgentSecure
// ==========================================
exports.assignDeliveryAgentSecure = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required.");
  }

  const callerUid = context.auth.uid;
  await requireRole(callerUid, ROLES.ADMIN);

  const orderId = validateNonEmptyString(data.orderId, "orderId");
  const deliveryAgentId = validateNonEmptyString(data.deliveryAgentId, "deliveryAgentId");

  return await db.runTransaction(async (transaction) => {
    const orderRef = db.collection("orders").doc(orderId);
    const agentRef = db.collection("users").doc(deliveryAgentId);

    const orderSnap = await transaction.get(orderRef);
    const agentSnap = await transaction.get(agentRef);

    if (!orderSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Order not found.");
    }
    if (!agentSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Delivery agent user not found.");
    }

    const orderData = orderSnap.data();
    const agentData = agentSnap.data();

    if (orderData.status !== ORDER_STATUS.READY_FOR_DELIVERY) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        `Order must be in '${ORDER_STATUS.READY_FOR_DELIVERY}' status to assign delivery agent.`
      );
    }

    if (agentData.role !== ROLES.DELIVERY) {
      throw new functions.https.HttpsError("failed-precondition", "Target user is not a DELIVERY agent.");
    }

    if (agentData.disabled === true) {
      throw new functions.https.HttpsError("failed-precondition", "Target delivery agent is disabled.");
    }

    transaction.update(orderRef, {
      deliveryAgentId,
      status: ORDER_STATUS.ASSIGNED_TO_DELIVERY,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const notifRef = db.collection("notifications").doc();
    transaction.set(notifRef, {
      notificationId: notifRef.id,
      userId: deliveryAgentId,
      title: "New Delivery Assigned",
      body: `You have been assigned to deliver order ${orderId}.`,
      type: "DELIVERY_ASSIGNED",
      read: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return {
      success: true,
      orderId,
      deliveryAgentId,
      status: ORDER_STATUS.ASSIGNED_TO_DELIVERY,
    };
  });
});

// ==========================================
// 5. manageProductSecure
// ==========================================
exports.manageProductSecure = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required.");
  }

  const callerUid = context.auth.uid;
  await requireRole(callerUid, ROLES.ADMIN);

  const action = validateNonEmptyString(data.action, "action");

  if (action === "CREATE") {
    const name = validateNonEmptyString(data.name, "name");
    
    if (data.sellingPrice === undefined) {
      throw new functions.https.HttpsError("invalid-argument", "Field 'sellingPrice' is required.");
    }

    const sellingPrice = requireNonNegativeNumber(data.sellingPrice, "sellingPrice");
    const quantity = requireNonNegativeInteger(data.quantity, "quantity");
    const discount = data.discount !== undefined ? requireNonNegativeNumber(data.discount, "discount") : 0;

    const productRef = db.collection("products").doc();
    const payload = {
      productId: productRef.id,
      name,
      sellingPrice,
      price: sellingPrice, // Backward compatibility read mirror
      quantity,
      reservedQuantity: 0,
      discount,
      status: "ACTIVE",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    await productRef.set(payload);
    return { success: true, productId: productRef.id, action: "CREATE" };
  } else if (action === "UPDATE") {
    const productId = validateNonEmptyString(data.productId, "productId");
    const productRef = db.collection("products").doc(productId);

    return await db.runTransaction(async (transaction) => {
      const productSnap = await transaction.get(productRef);
      if (!productSnap.exists) {
        throw new functions.https.HttpsError("not-found", "Product not found.");
      }

      const pData = productSnap.data();
      const updates = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };

      if (data.name !== undefined) updates.name = validateNonEmptyString(data.name, "name");
      if (data.status !== undefined) {
        const st = validateNonEmptyString(data.status, "status");
        if (!["ACTIVE", "INACTIVE"].includes(st)) {
          throw new functions.https.HttpsError("invalid-argument", "Invalid product status.");
        }
        updates.status = st;
      }

      if (data.sellingPrice !== undefined) {
        const pr = requireNonNegativeNumber(data.sellingPrice, "sellingPrice");
        updates.sellingPrice = pr;
        updates.price = pr;
      }

      if (data.discount !== undefined) {
        const dc = requireNonNegativeNumber(data.discount, "discount");
        updates.discount = dc;
      }

      let targetQuantity = requireNonNegativeInteger(pData.quantity, `products.${productId}.quantity`);
      if (data.quantity !== undefined) {
        const q = requireNonNegativeInteger(data.quantity, "quantity");
        targetQuantity = q;
        updates.quantity = q;
      }

      const currentReserved = requireNonNegativeInteger(pData.reservedQuantity, `products.${productId}.reservedQuantity`);
      if (targetQuantity < currentReserved) {
        throw new functions.https.HttpsError(
          "failed-precondition",
          `Cannot set total quantity (${targetQuantity}) below currently reserved quantity (${currentReserved}).`
        );
      }

      transaction.update(productRef, updates);
      return { success: true, productId, action: "UPDATE" };
    });
  } else {
    throw new functions.https.HttpsError("invalid-argument", "Unsupported action.");
  }
});

// ==========================================
// 6. updateOrderStatusStrict
// ==========================================
exports.updateOrderStatusStrict = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required.");
  }

  const orderId = validateNonEmptyString(data.orderId, "orderId");
  const rawStatus = data.nextStatus !== undefined ? data.nextStatus : data.targetStatus;
  const targetStatus = validateNonEmptyString(rawStatus, "nextStatus/targetStatus");
  const callerUid = context.auth.uid;

  const callerUserData = await getActiveUserData(callerUid);
  const callerRole = callerUserData.role;

  // Strict Role Allowlist Validation
  const allowedUpdateRoles = [ROLES.ADMIN, ROLES.WAREHOUSE, ROLES.DELIVERY];
  if (!allowedUpdateRoles.includes(callerRole)) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "User role is not authorized to update order status."
    );
  }

  return await db.runTransaction(async (transaction) => {
    const orderRef = db.collection("orders").doc(orderId);
    const orderSnap = await transaction.get(orderRef);

    if (!orderSnap.exists) {
      throw new functions.https.HttpsError("not-found", "Order not found.");
    }

    const orderData = orderSnap.data();
    const currentStatus = orderData.status;

    if (currentStatus === ORDER_STATUS.COMPLETED || currentStatus === ORDER_STATUS.CANCELLED) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        `Cannot change status of an order that is already ${currentStatus}.`
      );
    }

    if (targetStatus === ORDER_STATUS.DELIVERED || targetStatus === ORDER_STATUS.CANCELLED) {
      throw new functions.https.HttpsError(
        "permission-denied",
        "DELIVERED and CANCELLED statuses cannot be set directly via updateOrderStatusStrict."
      );
    }

    const allowed = ALLOWED_STATUS_TRANSITIONS[currentStatus] || [];
    if (!allowed.includes(targetStatus)) {
      throw new functions.https.HttpsError(
        "failed-precondition",
        `Transition from '${currentStatus}' to '${targetStatus}' is prohibited.`
      );
    }

    // Role-specific Transition Policies
    if (callerRole === ROLES.ADMIN) {
      // Explicit Policy: ADMIN cannot execute warehouse or delivery transitions via updateOrderStatusStrict
      if (
        (currentStatus === ORDER_STATUS.NEW && targetStatus === ORDER_STATUS.PREPARING) ||
        (currentStatus === ORDER_STATUS.PREPARING && targetStatus === ORDER_STATUS.READY_FOR_DELIVERY)
      ) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Admins cannot execute warehouse fulfillment operations."
        );
      }
      if (
        currentStatus === ORDER_STATUS.READY_FOR_DELIVERY &&
        targetStatus === ORDER_STATUS.ASSIGNED_TO_DELIVERY
      ) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Admins must use assignDeliveryAgentSecure to assign orders to delivery agents."
        );
      }
      if (
        currentStatus === ORDER_STATUS.ASSIGNED_TO_DELIVERY &&
        targetStatus === ORDER_STATUS.OUT_FOR_DELIVERY
      ) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Admins cannot move orders to OUT_FOR_DELIVERY directly."
        );
      }
    }

    if (callerRole === ROLES.WAREHOUSE) {
      const allowedWarehouseTransitions = [
        { from: ORDER_STATUS.NEW, to: ORDER_STATUS.PREPARING },
        { from: ORDER_STATUS.PREPARING, to: ORDER_STATUS.READY_FOR_DELIVERY },
      ];
      const isAllowed = allowedWarehouseTransitions.some(
        (t) => t.from === currentStatus && t.to === targetStatus
      );
      if (!isAllowed) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Warehouse role is not authorized for this transition."
        );
      }
    }

    if (callerRole === ROLES.DELIVERY) {
      if (orderData.deliveryAgentId !== callerUid) {
        throw new functions.https.HttpsError("permission-denied", "Not assigned to this order.");
      }
      if (
        currentStatus !== ORDER_STATUS.ASSIGNED_TO_DELIVERY ||
        targetStatus !== ORDER_STATUS.OUT_FOR_DELIVERY
      ) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Delivery agents can only move assigned orders from ASSIGNED_TO_DELIVERY to OUT_FOR_DELIVERY."
        );
      }
    }

    transaction.update(orderRef, {
      status: targetStatus,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return { success: true, orderId, previousStatus: currentStatus, status: targetStatus };
  });
});

// ==========================================
// 7. manageStaffSecure
// ==========================================
exports.manageStaffSecure = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Authentication required.");
  }

  const callerUid = context.auth.uid;
  await requireRole(callerUid, ROLES.ADMIN);

  const action = validateNonEmptyString(data.action, "action");
  const targetUid = validateNonEmptyString(data.targetUid, "targetUid");

  if (targetUid === callerUid) {
    throw new functions.https.HttpsError("permission-denied", "Admins cannot modify their own staff record.");
  }

  const userRef = db.collection("users").doc(targetUid);

  if (action === "TOGGLE_STATUS") {
    return await db.runTransaction(async (transaction) => {
      const userSnap = await transaction.get(userRef);
      if (!userSnap.exists) {
        throw new functions.https.HttpsError("not-found", "Target user not found.");
      }

      const targetData = userSnap.data();

      // Explicit Allowlist Verification for TOGGLE_STATUS
      const STAFF_ROLES = [ROLES.ADMIN, ROLES.WAREHOUSE, ROLES.DELIVERY];
      if (!STAFF_ROLES.includes(targetData.role)) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Cannot toggle status of non-staff accounts via manageStaffSecure."
        );
      }

      const currentDisabled = targetData.disabled === true;
      transaction.update(userRef, {
        disabled: !currentDisabled,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      return { success: true, targetUid, disabled: !currentDisabled };
    });
  } else if (action === "UPDATE_ROLE") {
    const newRole = validateNonEmptyString(data.role, "role").toUpperCase();
    if (![ROLES.ADMIN, ROLES.WAREHOUSE, ROLES.DELIVERY].includes(newRole)) {
      throw new functions.https.HttpsError(
        "invalid-argument",
        "Target role must be a valid staff/admin role (ADMIN, WAREHOUSE, DELIVERY)."
      );
    }

    return await db.runTransaction(async (transaction) => {
      const targetSnap = await transaction.get(userRef);
      if (!targetSnap.exists) {
        throw new functions.https.HttpsError("not-found", "Target user not found.");
      }

      const targetData = targetSnap.data();
      if (targetData.role === ROLES.CUSTOMER) {
        throw new functions.https.HttpsError(
          "permission-denied",
          "Cannot convert CUSTOMER accounts via manageStaffSecure."
        );
      }

      transaction.update(userRef, {
        role: newRole,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      return { success: true, targetUid, role: newRole };
    });
  } else {
    throw new functions.https.HttpsError("invalid-argument", "Unsupported staff management action.");
  }
});

