import {
  integer,
  pgTable,
  text,
  timestamp,
  varchar,
  decimal,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

export const usersTable = pgTable("users", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  name: varchar({ length: 255 }).notNull(),
  image: text(),
  email: varchar({ length: 255 }).notNull().unique(),
  password: varchar({ length: 255 }).notNull(),
  createdAt: timestamp().notNull().defaultNow(),
  updatedAt: timestamp().notNull().defaultNow(),
});

export const categoriesTable = pgTable("categories", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  userId: integer("user_id")
    .notNull()
    .references(() => usersTable.id, { onDelete: "cascade" }),
  name: varchar({ length: 255 }).notNull(),
  createdAt: timestamp().notNull().defaultNow(),
  updatedAt: timestamp().notNull().defaultNow(),
});

export const productsTable = pgTable("products", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  slug: varchar({ length: 255 }).notNull().unique(),
  userId: integer("user_id")
    .notNull()
    .references(() => usersTable.id, { onDelete: "cascade" }),
  categoryId: integer("category_id").references(() => categoriesTable.id, {
    onDelete: "set null",
  }),
  sku: varchar({ length: 100 }).notNull(),
  name: varchar({ length: 255 }).notNull(),
  description: text(),
  stockCount: integer("stock_count").notNull().default(0),
  price: decimal("price", { precision: 10, scale: 2 }),
  createdAt: timestamp().notNull().defaultNow(),
  updatedAt: timestamp().notNull().defaultNow(),
});

export const productImagesTable = pgTable("product_images", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  productId: integer("product_id")
    .notNull()
    .references(() => productsTable.id, { onDelete: "cascade" }),
  url: text().notNull(),
  alt: varchar({ length: 255 }),
  isPrimary: integer("is_primary").default(0),
  createdAt: timestamp().notNull().defaultNow(),
});

export const ordersTable = pgTable("orders", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  userId: integer("user_id")
    .notNull()
    .references(() => usersTable.id, { onDelete: "cascade" }),
  status: varchar({ length: 50 }).notNull().default("pending"),
  total: decimal("total", { precision: 10, scale: 2 }).notNull(),
  createdAt: timestamp().notNull().defaultNow(),
  updatedAt: timestamp().notNull().defaultNow(),
});

export const orderItemsTable = pgTable("order_items", {
  id: integer().primaryKey().generatedAlwaysAsIdentity(),
  orderId: integer("order_id")
    .notNull()
    .references(() => ordersTable.id, { onDelete: "cascade" }),
  productId: integer("product_id")
    .notNull()
    .references(() => productsTable.id, { onDelete: "cascade" }),
  quantity: integer().notNull(),
  price: decimal("price", { precision: 10, scale: 2 }).notNull(),
  createdAt: timestamp().notNull().defaultNow(),
});

export const usersRelations = relations(usersTable, ({ many }) => ({
  categories: many(categoriesTable),
  products: many(productsTable),
  orders: many(ordersTable),
}));

export const categoriesRelations = relations(
  categoriesTable,
  ({ one, many }) => ({
    user: one(usersTable, {
      fields: [categoriesTable.userId],
      references: [usersTable.id],
    }),
    products: many(productsTable),
  })
);

export const productsRelations = relations(productsTable, ({ one, many }) => ({
  user: one(usersTable, {
    fields: [productsTable.userId],
    references: [usersTable.id],
  }),
  category: one(categoriesTable, {
    fields: [productsTable.categoryId],
    references: [categoriesTable.id],
  }),
  images: many(productImagesTable),
  orderItems: many(orderItemsTable),
}));

export const productImagesRelations = relations(
  productImagesTable,
  ({ one }) => ({
    product: one(productsTable, {
      fields: [productImagesTable.productId],
      references: [productsTable.id],
    }),
  })
);

export const ordersRelations = relations(ordersTable, ({ one, many }) => ({
  user: one(usersTable, {
    fields: [ordersTable.userId],
    references: [usersTable.id],
  }),
  items: many(orderItemsTable),
}));

export const orderItemsRelations = relations(orderItemsTable, ({ one }) => ({
  order: one(ordersTable, {
    fields: [orderItemsTable.orderId],
    references: [ordersTable.id],
  }),
  product: one(productsTable, {
    fields: [orderItemsTable.productId],
    references: [productsTable.id],
  }),
}));
