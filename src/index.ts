import "dotenv/config";
import { Elysia, status, t } from "elysia";
import { openapi } from "@elysiajs/openapi";
import { cors } from "@elysiajs/cors";
import { jwt } from "@elysiajs/jwt";
import { db } from "./db";
import {
  usersTable,
  productsTable,
  productImagesTable,
  categoriesTable,
  ordersTable,
  orderItemsTable,
} from "./db/schema";
import { eq, and, desc, asc, sql, or } from "drizzle-orm";
import { uploadFile } from "./utils/upload";

const startTimes = new WeakMap<Request, number>();

const formatTime = (date: Date = new Date()): string => {
  const hours = date.getHours().toString().padStart(2, "0");
  const minutes = date.getMinutes().toString().padStart(2, "0");
  const seconds = date.getSeconds().toString().padStart(2, "0");
  const milliseconds = date.getMilliseconds().toString().padStart(3, "0");
  return `${hours}:${minutes}:${seconds}.${milliseconds}`;
};

const app = new Elysia()
  .onBeforeHandle(({ request }) => {
    const { method, url } = request;
    const path = new URL(url).pathname;
    const start = Date.now();
    startTimes.set(request, start);
    console.log(`➡️  ${method} ${path}   ← received at ${formatTime()}`);
  })
  .onAfterHandle(({ request, response }) => {
    const { method, url } = request;
    const path = new URL(url).pathname;
    const start = startTimes.get(request) || Date.now();
    const ms = Date.now() - start;
    const status = response instanceof Response ? response.status : 200;
    console.log(
      `⬅️  ${method} ${path} → ${status} (${ms}ms)   at ${formatTime()}`
    );
  })
  .use(
    openapi({
      documentation: {
        info: {
          title: "Elysia API",
          version: "1.0.0",
          description: "REST API with JWT authentication",
        },
        components: {
          securitySchemes: {
            bearerAuth: {
              type: "http",
              scheme: "bearer",
              bearerFormat: "JWT",
              description: "JWT token obtained from the /signin endpoint",
            },
          },
        },
      },
    })
  )
  .use(cors())
  .use(
    jwt({
      name: "jwt",
      secret: process.env.JWT_SECRET || "your-secret-key-change-in-production",
    })
  )
  .get("/", () => "Hello Elysia")
  .get("/html", async () => {
    try {
      const file = Bun.file("index.html");
      return new Response(file, {
        headers: {
          "Content-Type": "text/html",
        },
      });
    } catch (error) {
      return status(500, { message: "Failed to load HTML file" });
    }
  })
  .post(
    "/test-upload",
    async ({ body }) => {
      try {
        const { file, files, type } = body;

        if (!file && (!files || files.length === 0)) {
          return status(400, { message: "No file provided" });
        }

        const uploadType = type || "test";

        if (file) {
          const url = await uploadFile(file, uploadType);
          return {
            success: true,
            file: {
              name: file.name,
              type: file.type,
              size: file.size,
              url,
            },
          };
        }

        if (files && files.length > 0) {
          const uploadResults = await Promise.all(
            files.map(async (f: File) => {
              const url = await uploadFile(f, uploadType);
              return {
                name: f.name,
                type: f.type,
                size: f.size,
                url,
              };
            })
          );

          return {
            success: true,
            files: uploadResults,
            count: uploadResults.length,
          };
        }

        return status(400, { message: "No file provided" });
      } catch (error) {
        console.error("Upload test error:", error);
        return status(500, {
          message: "Upload failed",
          error: error instanceof Error ? error.message : "Unknown error",
        });
      }
    },
    {
      body: t.Object({
        file: t.Optional(
          t.File({
            description: "Single file to upload",
          })
        ),
        files: t.Optional(
          t.Files({
            description: "Multiple files to upload",
          })
        ),
        type: t.Optional(
          t.String({
            description: "File type prefix for naming (default: 'test')",
            examples: ["test", "image", "document"],
          })
        ),
      }),
      detail: {
        summary: "Test file upload",
        description:
          "Test endpoint for file upload functionality. Uploads one or more files and returns the uploaded file URLs. Useful for testing the upload service configuration.",
        tags: ["testing"],
        operationId: "testUpload",
      },
      response: {
        200: t.Union([
          t.Object({
            success: t.Boolean(),
            file: t.Object({
              name: t.String(),
              type: t.String(),
              size: t.Number(),
              url: t.String(),
            }),
          }),
          t.Object({
            success: t.Boolean(),
            files: t.Array(
              t.Object({
                name: t.String(),
                type: t.String(),
                size: t.Number(),
                url: t.String(),
              })
            ),
            count: t.Number(),
          }),
        ]),
        400: t.Object({
          message: t.String(),
        }),
        500: t.Object({
          message: t.String(),
          error: t.String(),
        }),
      },
    }
  )
  .post(
    "/signin",
    async ({ body, jwt }) => {
      try {
        const { email, password } = body;

        const users = await db
          .select()
          .from(usersTable)
          .where(eq(usersTable.email, email))
          .limit(1);

        if (users.length === 0) {
          return status(401, { message: "Invalid email or password" });
        }

        const user = users[0];
        const isValid = await Bun.password.verify(password, user.password);

        if (!isValid) {
          return status(401, { message: "Invalid email or password" });
        }

        const token = await jwt.sign({
          userId: user.id,
          email: user.email,
        });

        return {
          token,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            image: user.image || "",
          },
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      body: t.Object({
        email: t.String({
          format: "email",
          description: "User's email address",
          examples: ["user@example.com"],
        }),
        password: t.String({
          minLength: 8,
          maxLength: 255,
          description: "User's password (minimum 8 characters)",
          examples: ["SecurePassword123"],
        }),
      }),
      detail: {
        summary: "Sign in user",
        description:
          "Authenticates a user with their email and password credentials. Returns a JWT token that should be included in subsequent requests via the Authorization header as 'Bearer <token>'.",
        tags: ["authentication"],
        operationId: "signIn",
      },
      response: {
        200: t.Object(
          {
            token: t.String({ description: "JWT authentication token" }),
            user: t.Object({
              id: t.Number({ description: "User ID" }),
              name: t.String({ description: "User's full name" }),
              email: t.String({ description: "User's email address" }),
              image: t.Union([t.String(), t.Null()], {
                description: "User's profile image URL",
              }),
            }),
          },
          { description: "Authentication successful" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Invalid email or password" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/profile",
    async ({ jwt, headers }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;

        const user = await db
          .select()
          .from(usersTable)
          .where(eq(usersTable.id, userId))
          .limit(1);

        if (user.length === 0) {
          return status(404, { message: "User not found" });
        }

        return {
          id: user[0].id,
          name: user[0].name,
          email: user[0].email,
          image: user[0].image || "",
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      detail: {
        summary: "Get user profile",
        description:
          "Retrieves the authenticated user's profile information. Requires a valid JWT token in the Authorization header as 'Bearer <token>'.",
        tags: ["authentication"],
        operationId: "getProfile",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            id: t.Number({ description: "User ID" }),
            name: t.String({ description: "User's full name" }),
            email: t.String({ description: "User's email address" }),
            image: t.String({ description: "User's profile image URL" }),
          },
          { description: "User profile retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "User not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/stats",
    async ({ jwt, headers }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;

        const productsCountResult = await db
          .select({ count: sql<number>`count(*)` })
          .from(productsTable)
          .where(eq(productsTable.userId, userId));

        const categoriesCountResult = await db
          .select({ count: sql<number>`count(*)` })
          .from(categoriesTable)
          .where(eq(categoriesTable.userId, userId));

        const ordersByStatusResult = await db
          .select({
            status: ordersTable.status,
            count: sql<number>`count(*)`,
          })
          .from(ordersTable)
          .where(eq(ordersTable.userId, userId))
          .groupBy(ordersTable.status);

        const totalRevenueResult = await db
          .select({
            total: sql<string>`COALESCE(SUM(${ordersTable.total}), 0)`,
          })
          .from(ordersTable)
          .where(eq(ordersTable.userId, userId));

        const revenueByStatusResult = await db
          .select({
            status: ordersTable.status,
            total: sql<string>`COALESCE(SUM(${ordersTable.total}), 0)`,
          })
          .from(ordersTable)
          .where(eq(ordersTable.userId, userId))
          .groupBy(ordersTable.status);

        const totalProducts = Number(productsCountResult[0]?.count || 0);
        const totalCategories = Number(categoriesCountResult[0]?.count || 0);
        const overallTotal = parseFloat(totalRevenueResult[0]?.total || "0");

        const ordersByStatus = ordersByStatusResult.map((item) => ({
          status: item.status,
          count: Number(item.count || 0),
        }));

        const revenueByStatus: Record<string, number> = {};
        revenueByStatusResult.forEach((item) => {
          revenueByStatus[item.status] = parseFloat(item.total || "0");
        });

        const pendingTotal = revenueByStatus["pending"] || 0;
        const completedTotal = revenueByStatus["completed"] || 0;
        const cancelledTotal = revenueByStatus["cancelled"] || 0;

        return {
          totalProducts,
          totalCategories,
          ordersByStatus,
          revenue: {
            overallTotal,
            pendingTotal,
            completedTotal,
            cancelledTotal,
          },
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      detail: {
        summary: "Get user statistics",
        description:
          "Retrieves statistics for the authenticated user including total products, total categories, orders grouped by status, and revenue totals. Requires a valid JWT token in the Authorization header as 'Bearer <token>'.",
        tags: ["statistics"],
        operationId: "getUserStats",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            totalProducts: t.Number({
              description: "Total number of products for the user",
            }),
            totalCategories: t.Number({
              description: "Total number of categories for the user",
            }),
            ordersByStatus: t.Array(
              t.Object({
                status: t.String({
                  description: "Order status",
                }),
                count: t.Number({
                  description: "Number of orders with this status",
                }),
              }),
              {
                description:
                  "Array of order counts grouped by status (e.g., 'pending', 'completed', 'cancelled')",
              }
            ),
            revenue: t.Object(
              {
                overallTotal: t.Number({
                  description: "Total revenue from all orders",
                }),
                pendingTotal: t.Number({
                  description: "Total revenue from pending orders",
                }),
                completedTotal: t.Number({
                  description: "Total revenue from completed orders",
                }),
                cancelledTotal: t.Number({
                  description: "Total revenue from cancelled orders",
                }),
              },
              {
                description: "Revenue statistics grouped by order status",
              }
            ),
          },
          { description: "User statistics retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .post(
    "/signup",
    async ({ body }) => {
      try {
        const { name, email, password, confirmPassword } = body;

        if (password !== confirmPassword)
          return status(400, { message: "Passwords do not match" });

        const user = await db
          .select()
          .from(usersTable)
          .where(eq(usersTable.email, email))
          .limit(1);

        if (user.length > 0)
          return status(400, { message: "User already exists" });

        const hash = await Bun.password.hash(password);

        await db.insert(usersTable).values({
          name,
          email,
          password: hash,
        });

        return status(201, { message: "User created successfully" });
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      body: t.Object({
        name: t.String({
          minLength: 3,
          maxLength: 255,
          description: "User's full name (minimum 3 characters)",
          examples: ["John Doe"],
        }),
        email: t.String({
          format: "email",
          description: "User's email address (must be unique)",
          examples: ["user@example.com"],
        }),
        password: t.String({
          minLength: 8,
          maxLength: 255,
          description: "User's password (minimum 8 characters)",
          examples: ["SecurePassword123"],
        }),
        confirmPassword: t.String({
          minLength: 8,
          maxLength: 255,
          description: "Password confirmation (must match the password field)",
          examples: ["SecurePassword123"],
        }),
      }),
      detail: {
        summary: "Sign up user",
        description:
          "Creates a new user account. The password and confirmPassword fields must match. After successful registration, use the /signin endpoint to obtain a JWT token.",
        tags: ["authentication"],
        operationId: "signUp",
      },
      response: {
        201: t.Object(
          {
            message: t.String(),
          },
          { description: "User account created successfully" }
        ),
        400: t.Object(
          {
            message: t.String(),
          },
          {
            description:
              "Bad request - Passwords don't match or user already exists",
          }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .post(
    "/products",
    async ({ jwt, headers, body }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const {
          name,
          slug,
          sku,
          description,
          stockCount,
          price,
          categoryId,
          images,
        } = body;

        if (!name || !slug || !sku) {
          return status(400, {
            message: "Name, slug, and SKU are required",
          });
        }

        const existingProduct = await db
          .select()
          .from(productsTable)
          .where(eq(productsTable.slug, slug))
          .limit(1);

        if (existingProduct.length > 0) {
          return status(400, {
            message: "Product with this slug already exists",
          });
        }

        const existingSku = await db
          .select()
          .from(productsTable)
          .where(eq(productsTable.sku, sku))
          .limit(1);

        if (existingSku.length > 0) {
          return status(400, {
            message: "Product with this SKU already exists",
          });
        }

        const productData: any = {
          slug,
          userId,
          sku,
          name,
          stockCount: stockCount ? parseInt(stockCount.toString()) : 0,
        };

        if (description) productData.description = description;
        if (price) productData.price = price.toString();
        if (categoryId)
          productData.categoryId = parseInt(categoryId.toString());

        const [product] = await db
          .insert(productsTable)
          .values(productData)
          .returning();

        const imageUrls: string[] = [];

        if (images && images.length > 0) {
          for (let i = 0; i < images.length; i++) {
            const image = images[i];
            if (image instanceof File) {
              const url = await uploadFile(image, "product");
              imageUrls.push(url);

              await db.insert(productImagesTable).values({
                productId: product.id,
                url,
                alt: name,
                isPrimary: i === 0 ? 1 : 0,
              });
            }
          }
        }

        return status(201, {
          id: product.id,
          slug: product.slug,
          userId: product.userId,
          categoryId: product.categoryId,
          sku: product.sku,
          name: product.name,
          description: product.description,
          stockCount: product.stockCount,
          price: product.price,
          images: imageUrls,
          createdAt: product.createdAt,
          updatedAt: product.updatedAt,
        });
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      body: t.Object({
        name: t.String({
          minLength: 1,
          maxLength: 255,
          description: "Product name",
          examples: ["Wireless Mouse"],
        }),
        slug: t.String({
          minLength: 1,
          maxLength: 255,
          description: "URL-friendly product identifier (must be unique)",
          examples: ["wireless-mouse"],
        }),
        sku: t.String({
          minLength: 1,
          maxLength: 100,
          description: "Stock Keeping Unit (must be unique)",
          examples: ["WM-001"],
        }),
        description: t.Optional(
          t.String({
            description: "Product description",
            examples: ["Ergonomic wireless mouse with 2.4GHz connectivity"],
          })
        ),
        stockCount: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Number of items in stock",
            examples: [100],
          })
        ),
        price: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Product price",
            examples: [29.99],
          })
        ),
        categoryId: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Category ID (optional)",
            examples: [1],
          })
        ),
        images: t.Optional(
          t.Files({
            description: "Product images (multiple files allowed)",
          })
        ),
      }),
      detail: {
        summary: "Create a new product",
        description:
          "Creates a new product with optional images. Requires authentication via JWT token. The first uploaded image will be set as the primary image.",
        tags: ["products"],
        operationId: "createProduct",
        security: [{ bearerAuth: [] }],
      },
      response: {
        201: t.Object(
          {
            id: t.Number({ description: "Product ID" }),
            slug: t.String({ description: "Product slug" }),
            userId: t.Number({ description: "User ID of the product owner" }),
            categoryId: t.Union([t.Number(), t.Null()], {
              description: "Category ID",
            }),
            sku: t.String({ description: "Stock Keeping Unit" }),
            name: t.String({ description: "Product name" }),
            description: t.Union([t.String(), t.Null()], {
              description: "Product description",
            }),
            stockCount: t.Number({ description: "Number of items in stock" }),
            price: t.Union([t.String(), t.Null()], {
              description: "Product price",
            }),
            images: t.Array(t.String(), {
              description: "Array of uploaded image URLs",
            }),
            createdAt: t.Date({ description: "Creation timestamp" }),
            updatedAt: t.Date({ description: "Last update timestamp" }),
          },
          { description: "Product created successfully" }
        ),
        400: t.Object(
          {
            message: t.String(),
          },
          {
            description:
              "Bad request - Missing required fields, duplicate slug/SKU, or invalid data",
          }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/products",
    async ({ jwt, headers, query }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const page = query.page ? parseInt(query.page.toString()) : 1;
        const limit = query.limit ? parseInt(query.limit.toString()) : 10;
        const offset = (page - 1) * limit;
        const stockStatus = (query as any).stockStatus
          ? (query as any).stockStatus.toString()
          : null;
        const orderBy = (query as any).orderBy
          ? (query as any).orderBy.toString()
          : "createdAt";
        const orderDirection =
          (query as any).orderDirection === "asc" ? asc : desc;

        let whereCondition = eq(productsTable.userId, userId);
        if (stockStatus === "in_stock") {
          whereCondition = and(
            eq(productsTable.userId, userId),
            sql`${productsTable.stockCount} > 0`
          ) as any;
        } else if (stockStatus === "out_of_stock") {
          whereCondition = and(
            eq(productsTable.userId, userId),
            eq(productsTable.stockCount, 0)
          ) as any;
        } else if (stockStatus === "low_stock") {
          const lowStockThreshold = (query as any).lowStockThreshold
            ? parseInt((query as any).lowStockThreshold.toString())
            : 10;
          whereCondition = and(
            eq(productsTable.userId, userId),
            sql`${productsTable.stockCount} > 0 AND ${productsTable.stockCount} <= ${lowStockThreshold}`
          ) as any;
        }

        let orderByClause;
        if (orderBy === "stockCount") {
          orderByClause = orderDirection(productsTable.stockCount);
        } else if (orderBy === "name") {
          orderByClause = orderDirection(productsTable.name);
        } else if (orderBy === "price") {
          orderByClause = orderDirection(productsTable.price);
        } else {
          orderByClause = orderDirection(productsTable.createdAt);
        }

        const products = await db
          .select()
          .from(productsTable)
          .where(whereCondition)
          .orderBy(orderByClause)
          .limit(limit)
          .offset(offset);

        const totalCountResult = await db
          .select({ count: sql<number>`count(*)` })
          .from(productsTable)
          .where(whereCondition);

        const totalCount = Number(totalCountResult[0]?.count || 0);

        const productsWithImages = await Promise.all(
          products.map(async (product) => {
            const images = await db
              .select()
              .from(productImagesTable)
              .where(eq(productImagesTable.productId, product.id));

            return {
              ...product,
              images: images.map((img) => ({
                id: img.id,
                url: img.url,
                alt: img.alt,
                isPrimary: img.isPrimary === 1,
              })),
            };
          })
        );

        return {
          products: productsWithImages,
          pagination: {
            page,
            limit,
            total: totalCount,
            totalPages: Math.ceil(totalCount / limit),
          },
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      query: t.Object({
        page: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Page number (default: 1)",
            examples: [1],
          })
        ),
        limit: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Items per page (default: 10)",
            examples: [10],
          })
        ),
        stockStatus: t.Optional(
          t.String({
            description: "Filter products by stock status",
            examples: ["in_stock", "out_of_stock", "low_stock"],
          })
        ),
        lowStockThreshold: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Threshold for low stock filter (default: 10)",
            examples: [10],
          })
        ),
        orderBy: t.Optional(
          t.String({
            description: "Field to order by",
            examples: ["createdAt", "stockCount", "name", "price"],
          })
        ),
        orderDirection: t.Optional(
          t.String({
            description: "Order direction",
            examples: ["asc", "desc"],
          })
        ),
      }),
      detail: {
        summary: "Get user's products",
        description:
          "Retrieves a paginated list of products for the authenticated user. Supports filtering by stock status (in_stock, out_of_stock, low_stock) and ordering by createdAt, stockCount, name, or price. Requires JWT token.",
        tags: ["products"],
        operationId: "getUserProducts",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            products: t.Array(
              t.Object({
                id: t.Number(),
                slug: t.String(),
                userId: t.Number(),
                categoryId: t.Union([t.Number(), t.Null()]),
                sku: t.String(),
                name: t.String(),
                description: t.Union([t.String(), t.Null()]),
                stockCount: t.Number(),
                price: t.Union([t.String(), t.Null()]),
                createdAt: t.Date(),
                updatedAt: t.Date(),
                images: t.Array(
                  t.Object({
                    id: t.Number(),
                    url: t.String(),
                    alt: t.Union([t.String(), t.Null()]),
                    isPrimary: t.Boolean(),
                  })
                ),
              })
            ),
            pagination: t.Object({
              page: t.Number(),
              limit: t.Number(),
              total: t.Number(),
              totalPages: t.Number(),
            }),
          },
          { description: "Products retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/products/search",
    async ({ jwt, headers, query }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const searchTerm = query.q?.toString().trim() || "";

        if (!searchTerm) {
          return status(400, {
            message: "Search query parameter 'q' is required",
          });
        }

        const page = query.page ? parseInt(query.page.toString()) : 1;
        const limit = query.limit ? parseInt(query.limit.toString()) : 10;
        const offset = (page - 1) * limit;

        const searchPattern = `%${searchTerm}%`;

        const products = await db
          .select()
          .from(productsTable)
          .where(
            and(
              eq(productsTable.userId, userId),
              or(
                sql`${productsTable.name} ILIKE ${searchPattern}`,
                sql`${productsTable.description} ILIKE ${searchPattern}`,
                sql`${productsTable.sku} ILIKE ${searchPattern}`,
                sql`${productsTable.slug} ILIKE ${searchPattern}`
              )
            )
          )
          .orderBy(desc(productsTable.createdAt))
          .limit(limit)
          .offset(offset);

        const totalCountResult = await db
          .select({ count: sql<number>`count(*)` })
          .from(productsTable)
          .where(
            and(
              eq(productsTable.userId, userId),
              or(
                sql`${productsTable.name} ILIKE ${searchPattern}`,
                sql`${productsTable.description} ILIKE ${searchPattern}`,
                sql`${productsTable.sku} ILIKE ${searchPattern}`,
                sql`${productsTable.slug} ILIKE ${searchPattern}`
              )
            )
          );

        const totalCount = Number(totalCountResult[0]?.count || 0);

        const productsWithImages = await Promise.all(
          products.map(async (product) => {
            const images = await db
              .select()
              .from(productImagesTable)
              .where(eq(productImagesTable.productId, product.id));

            return {
              ...product,
              images: images.map((img) => ({
                id: img.id,
                url: img.url,
                alt: img.alt,
                isPrimary: img.isPrimary === 1,
              })),
            };
          })
        );

        return {
          products: productsWithImages,
          pagination: {
            page,
            limit,
            total: totalCount,
            totalPages: Math.ceil(totalCount / limit),
          },
          searchTerm,
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      query: t.Object({
        q: t.String({
          minLength: 1,
          description: "Search query term",
          examples: ["wireless mouse"],
        }),
        page: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Page number (default: 1)",
            examples: [1],
          })
        ),
        limit: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Items per page (default: 10)",
            examples: [10],
          })
        ),
      }),
      detail: {
        summary: "Search products",
        description:
          "Searches products by name, description, SKU, or slug. Returns a paginated list of matching products for the authenticated user. Requires JWT token.",
        tags: ["products"],
        operationId: "searchProducts",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            products: t.Array(
              t.Object({
                id: t.Number(),
                slug: t.String(),
                userId: t.Number(),
                categoryId: t.Union([t.Number(), t.Null()]),
                sku: t.String(),
                name: t.String(),
                description: t.Union([t.String(), t.Null()]),
                stockCount: t.Number(),
                price: t.Union([t.String(), t.Null()]),
                createdAt: t.Date(),
                updatedAt: t.Date(),
                images: t.Array(
                  t.Object({
                    id: t.Number(),
                    url: t.String(),
                    alt: t.Union([t.String(), t.Null()]),
                    isPrimary: t.Boolean(),
                  })
                ),
              })
            ),
            pagination: t.Object({
              page: t.Number(),
              limit: t.Number(),
              total: t.Number(),
              totalPages: t.Number(),
            }),
            searchTerm: t.String(),
          },
          { description: "Products retrieved successfully" }
        ),
        400: t.Object(
          {
            message: t.String(),
          },
          { description: "Bad request - Missing search query parameter" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/products/:id",
    async ({ jwt, headers, params }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const productId = parseInt(params.id);

        const product = await db
          .select()
          .from(productsTable)
          .where(
            and(
              eq(productsTable.id, productId),
              eq(productsTable.userId, userId)
            )
          )
          .limit(1);

        if (product.length === 0) {
          return status(404, { message: "Product not found" });
        }

        const images = await db
          .select()
          .from(productImagesTable)
          .where(eq(productImagesTable.productId, productId));

        return {
          ...product[0],
          images: images.map((img) => ({
            id: img.id,
            url: img.url,
            alt: img.alt,
            isPrimary: img.isPrimary === 1,
          })),
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        id: t.String({ description: "Product ID" }),
      }),
      detail: {
        summary: "Get product by ID",
        description:
          "Retrieves a specific product by its ID. The product must belong to the authenticated user. Requires JWT token.",
        tags: ["products"],
        operationId: "getProductById",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            id: t.Number(),
            slug: t.String(),
            userId: t.Number(),
            categoryId: t.Union([t.Number(), t.Null()]),
            sku: t.String(),
            name: t.String(),
            description: t.Union([t.String(), t.Null()]),
            stockCount: t.Number(),
            price: t.Union([t.String(), t.Null()]),
            createdAt: t.Date(),
            updatedAt: t.Date(),
            images: t.Array(
              t.Object({
                id: t.Number(),
                url: t.String(),
                alt: t.Union([t.String(), t.Null()]),
                isPrimary: t.Boolean(),
              })
            ),
          },
          { description: "Product retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Product not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/products/sku/:sku",
    async ({ jwt, headers, params }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;

        const product = await db
          .select()
          .from(productsTable)
          .where(
            and(
              eq(productsTable.sku, params.sku),
              eq(productsTable.userId, userId)
            )
          )
          .limit(1);

        if (product.length === 0) {
          return status(404, { message: "Product not found" });
        }

        const images = await db
          .select()
          .from(productImagesTable)
          .where(eq(productImagesTable.productId, product[0].id));

        return {
          ...product[0],
          images: images.map((img) => ({
            id: img.id,
            url: img.url,
            alt: img.alt,
            isPrimary: img.isPrimary === 1,
          })),
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        sku: t.String({ description: "Product SKU" }),
      }),
      detail: {
        summary: "Get product by SKU",
        description:
          "Retrieves a specific product by its SKU. The product must belong to the authenticated user. Requires JWT token.",
        tags: ["products"],
        operationId: "getProductBySku",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            id: t.Number(),
            slug: t.String(),
            userId: t.Number(),
            categoryId: t.Union([t.Number(), t.Null()]),
            sku: t.String(),
            name: t.String(),
            description: t.Union([t.String(), t.Null()]),
            stockCount: t.Number(),
            price: t.Union([t.String(), t.Null()]),
            createdAt: t.Date(),
            updatedAt: t.Date(),
            images: t.Array(
              t.Object({
                id: t.Number(),
                url: t.String(),
                alt: t.Union([t.String(), t.Null()]),
                isPrimary: t.Boolean(),
              })
            ),
          },
          { description: "Product retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Product not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/products/slug/:slug",
    async ({ jwt, headers, params }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;

        const product = await db
          .select()
          .from(productsTable)
          .where(
            and(
              eq(productsTable.slug, params.slug),
              eq(productsTable.userId, userId)
            )
          )
          .limit(1);

        if (product.length === 0) {
          return status(404, { message: "Product not found" });
        }

        const images = await db
          .select()
          .from(productImagesTable)
          .where(eq(productImagesTable.productId, product[0].id));

        return {
          ...product[0],
          images: images.map((img) => ({
            id: img.id,
            url: img.url,
            alt: img.alt,
            isPrimary: img.isPrimary === 1,
          })),
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        slug: t.String({ description: "Product slug" }),
      }),
      detail: {
        summary: "Get product by slug",
        description:
          "Retrieves a specific product by its slug. The product must belong to the authenticated user. Requires JWT token.",
        tags: ["products"],
        operationId: "getProductBySlug",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            id: t.Number(),
            slug: t.String(),
            userId: t.Number(),
            categoryId: t.Union([t.Number(), t.Null()]),
            sku: t.String(),
            name: t.String(),
            description: t.Union([t.String(), t.Null()]),
            stockCount: t.Number(),
            price: t.Union([t.String(), t.Null()]),
            createdAt: t.Date(),
            updatedAt: t.Date(),
            images: t.Array(
              t.Object({
                id: t.Number(),
                url: t.String(),
                alt: t.Union([t.String(), t.Null()]),
                isPrimary: t.Boolean(),
              })
            ),
          },
          { description: "Product retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Product not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/categories",
    async ({ jwt, headers }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;

        const categories = await db
          .select()
          .from(categoriesTable)
          .where(eq(categoriesTable.userId, userId))
          .orderBy(desc(categoriesTable.createdAt));

        return categories;
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      detail: {
        summary: "Get user's categories",
        description:
          "Retrieves all categories for the authenticated user. Requires JWT token.",
        tags: ["categories"],
        operationId: "getUserCategories",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Array(
          t.Object({
            id: t.Number(),
            userId: t.Number(),
            name: t.String(),
            createdAt: t.Date(),
            updatedAt: t.Date(),
          }),
          { description: "Categories retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/categories/:categoryId/products",
    async ({ jwt, headers, params, query }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const categoryId = parseInt(params.categoryId);

        const category = await db
          .select()
          .from(categoriesTable)
          .where(
            and(
              eq(categoriesTable.id, categoryId),
              eq(categoriesTable.userId, userId)
            )
          )
          .limit(1);

        if (category.length === 0) {
          return status(404, { message: "Category not found" });
        }

        const page = query.page ? parseInt(query.page.toString()) : 1;
        const limit = query.limit ? parseInt(query.limit.toString()) : 10;
        const offset = (page - 1) * limit;

        const products = await db
          .select()
          .from(productsTable)
          .where(
            and(
              eq(productsTable.userId, userId),
              eq(productsTable.categoryId, categoryId)
            )
          )
          .orderBy(desc(productsTable.createdAt))
          .limit(limit)
          .offset(offset);

        const totalCountResult = await db
          .select({ count: sql<number>`count(*)` })
          .from(productsTable)
          .where(
            and(
              eq(productsTable.userId, userId),
              eq(productsTable.categoryId, categoryId)
            )
          );

        const totalCount = Number(totalCountResult[0]?.count || 0);

        const productsWithImages = await Promise.all(
          products.map(async (product) => {
            const images = await db
              .select()
              .from(productImagesTable)
              .where(eq(productImagesTable.productId, product.id));

            return {
              ...product,
              images: images.map((img) => ({
                id: img.id,
                url: img.url,
                alt: img.alt,
                isPrimary: img.isPrimary === 1,
              })),
            };
          })
        );

        return {
          category: category[0],
          products: productsWithImages,
          pagination: {
            page,
            limit,
            total: totalCount,
            totalPages: Math.ceil(totalCount / limit),
          },
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        categoryId: t.String({ description: "Category ID" }),
      }),
      query: t.Object({
        page: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Page number (default: 1)",
            examples: [1],
          })
        ),
        limit: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Items per page (default: 10)",
            examples: [10],
          })
        ),
      }),
      detail: {
        summary: "Get products in a category",
        description:
          "Retrieves a paginated list of products in a specific category for the authenticated user. Requires JWT token.",
        tags: ["categories", "products"],
        operationId: "getCategoryProducts",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            category: t.Object({
              id: t.Number(),
              userId: t.Number(),
              name: t.String(),
              createdAt: t.Date(),
              updatedAt: t.Date(),
            }),
            products: t.Array(
              t.Object({
                id: t.Number(),
                slug: t.String(),
                userId: t.Number(),
                categoryId: t.Union([t.Number(), t.Null()]),
                sku: t.String(),
                name: t.String(),
                description: t.Union([t.String(), t.Null()]),
                stockCount: t.Number(),
                price: t.Union([t.String(), t.Null()]),
                createdAt: t.Date(),
                updatedAt: t.Date(),
                images: t.Array(
                  t.Object({
                    id: t.Number(),
                    url: t.String(),
                    alt: t.Union([t.String(), t.Null()]),
                    isPrimary: t.Boolean(),
                  })
                ),
              })
            ),
            pagination: t.Object({
              page: t.Number(),
              limit: t.Number(),
              total: t.Number(),
              totalPages: t.Number(),
            }),
          },
          { description: "Products retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Category not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .post(
    "/categories",
    async ({ jwt, headers, body }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const { name } = body;

        if (!name || name.trim().length === 0) {
          return status(400, { message: "Category name is required" });
        }

        const existingCategory = await db
          .select()
          .from(categoriesTable)
          .where(
            and(
              eq(categoriesTable.userId, userId),
              eq(categoriesTable.name, name.trim())
            )
          )
          .limit(1);

        if (existingCategory.length > 0) {
          return status(400, {
            message: "Category with this name already exists",
          });
        }

        const [category] = await db
          .insert(categoriesTable)
          .values({
            userId,
            name: name.trim(),
          })
          .returning();

        return status(201, category);
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      body: t.Object({
        name: t.String({
          minLength: 1,
          maxLength: 255,
          description: "Category name",
          examples: ["Electronics"],
        }),
      }),
      detail: {
        summary: "Create a new category",
        description:
          "Creates a new category for the authenticated user. Category names must be unique per user. Requires JWT token.",
        tags: ["categories"],
        operationId: "createCategory",
        security: [{ bearerAuth: [] }],
      },
      response: {
        201: t.Object(
          {
            id: t.Number({ description: "Category ID" }),
            userId: t.Number({ description: "User ID" }),
            name: t.String({ description: "Category name" }),
            createdAt: t.Date({ description: "Creation timestamp" }),
            updatedAt: t.Date({ description: "Last update timestamp" }),
          },
          { description: "Category created successfully" }
        ),
        400: t.Object(
          {
            message: t.String(),
          },
          {
            description:
              "Bad request - Missing category name or category already exists",
          }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .post(
    "/orders",
    async ({ jwt, headers, body }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const { items } = body;

        if (!items || !Array.isArray(items) || items.length === 0) {
          return status(400, {
            message: "Order must contain at least one item",
          });
        }

        let total = 0;
        const orderItemsData: Array<{
          productId: number;
          quantity: number;
          price: string;
        }> = [];

        for (const item of items) {
          const productId = parseInt(item.productId.toString());
          const quantity = parseInt(item.quantity.toString());

          if (quantity <= 0) {
            return status(400, {
              message: `Invalid quantity for product ${productId}`,
            });
          }

          const product = await db
            .select()
            .from(productsTable)
            .where(eq(productsTable.id, productId))
            .limit(1);

          if (product.length === 0) {
            return status(404, {
              message: `Product with ID ${productId} not found`,
            });
          }

          const productPrice = product[0].price;
          if (!productPrice) {
            return status(400, {
              message: `Product ${productId} does not have a price`,
            });
          }

          const itemPrice = parseFloat(productPrice.toString());
          const itemTotal = itemPrice * quantity;
          total += itemTotal;

          orderItemsData.push({
            productId,
            quantity,
            price: productPrice.toString(),
          });
        }

        const [order] = await db
          .insert(ordersTable)
          .values({
            userId,
            status: "pending",
            total: total.toString(),
          })
          .returning();

        await db.insert(orderItemsTable).values(
          orderItemsData.map((item) => ({
            orderId: order.id,
            productId: item.productId,
            quantity: item.quantity,
            price: item.price,
          }))
        );

        const orderItems = await db
          .select()
          .from(orderItemsTable)
          .where(eq(orderItemsTable.orderId, order.id));

        const itemsWithProducts = await Promise.all(
          orderItems.map(async (item) => {
            const product = await db
              .select()
              .from(productsTable)
              .where(eq(productsTable.id, item.productId))
              .limit(1);

            return {
              id: item.id,
              productId: item.productId,
              quantity: item.quantity,
              price: item.price,
              product: product[0]
                ? {
                    id: product[0].id,
                    name: product[0].name,
                    slug: product[0].slug,
                    sku: product[0].sku,
                  }
                : null,
            };
          })
        );

        return status(201, {
          id: order.id,
          userId: order.userId,
          status: order.status,
          total: order.total,
          items: itemsWithProducts,
          createdAt: order.createdAt,
          updatedAt: order.updatedAt,
        });
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      body: t.Object({
        items: t.Array(
          t.Object({
            productId: t.Union([t.Number(), t.String()], {
              description: "Product ID",
            }),
            quantity: t.Union([t.Number(), t.String()], {
              description: "Quantity",
            }),
          }),
          {
            minLength: 1,
            description: "Array of order items",
          }
        ),
      }),
      detail: {
        summary: "Create a new order",
        description:
          "Creates a new order with the specified items. Requires authentication via JWT token. Validates that all products exist and have prices.",
        tags: ["orders"],
        operationId: "createOrder",
        security: [{ bearerAuth: [] }],
      },
      response: {
        201: t.Object(
          {
            id: t.Number({ description: "Order ID" }),
            userId: t.Number({ description: "User ID" }),
            status: t.String({ description: "Order status" }),
            total: t.String({ description: "Order total" }),
            items: t.Array(
              t.Object({
                id: t.Number(),
                productId: t.Number(),
                quantity: t.Number(),
                price: t.String(),
                product: t.Union([
                  t.Object({
                    id: t.Number(),
                    name: t.String(),
                    slug: t.String(),
                    sku: t.String(),
                  }),
                  t.Null(),
                ]),
              })
            ),
            createdAt: t.Date({ description: "Creation timestamp" }),
            updatedAt: t.Date({ description: "Last update timestamp" }),
          },
          { description: "Order created successfully" }
        ),
        400: t.Object(
          {
            message: t.String(),
          },
          {
            description:
              "Bad request - Invalid items, missing products, or products without prices",
          }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Product not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/orders",
    async ({ jwt, headers, query }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const page = query.page ? parseInt(query.page.toString()) : 1;
        const limit = query.limit ? parseInt(query.limit.toString()) : 10;
        const offset = (page - 1) * limit;
        const statusFilter = (query as any).status
          ? (query as any).status.toString()
          : null;
        const orderBy = (query as any).orderBy
          ? (query as any).orderBy.toString()
          : "createdAt";
        const orderDirection =
          (query as any).orderDirection === "asc" ? asc : desc;

        let whereCondition = eq(ordersTable.userId, userId);
        if (statusFilter) {
          whereCondition = and(
            eq(ordersTable.userId, userId),
            eq(ordersTable.status, statusFilter)
          ) as any;
        }

        let orderByClause;
        if (orderBy === "status") {
          orderByClause = orderDirection(ordersTable.status);
        } else if (orderBy === "total") {
          orderByClause = orderDirection(ordersTable.total);
        } else {
          orderByClause = orderDirection(ordersTable.createdAt);
        }

        const orders = await db
          .select()
          .from(ordersTable)
          .where(whereCondition)
          .orderBy(orderByClause)
          .limit(limit)
          .offset(offset);

        const totalCountResult = await db
          .select({ count: sql<number>`count(*)` })
          .from(ordersTable)
          .where(whereCondition);

        const totalCount = Number(totalCountResult[0]?.count || 0);

        const ordersWithItems = await Promise.all(
          orders.map(async (order) => {
            const orderItems = await db
              .select()
              .from(orderItemsTable)
              .where(eq(orderItemsTable.orderId, order.id));

            const itemsWithProducts = await Promise.all(
              orderItems.map(async (item) => {
                const product = await db
                  .select()
                  .from(productsTable)
                  .where(eq(productsTable.id, item.productId))
                  .limit(1);

                return {
                  id: item.id,
                  productId: item.productId,
                  quantity: item.quantity,
                  price: item.price,
                  product: product[0]
                    ? {
                        id: product[0].id,
                        name: product[0].name,
                        slug: product[0].slug,
                        sku: product[0].sku,
                      }
                    : null,
                };
              })
            );

            return {
              ...order,
              items: itemsWithProducts,
            };
          })
        );

        return {
          orders: ordersWithItems,
          pagination: {
            page,
            limit,
            total: totalCount,
            totalPages: Math.ceil(totalCount / limit),
          },
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      query: t.Object({
        page: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Page number (default: 1)",
            examples: [1],
          })
        ),
        limit: t.Optional(
          t.Union([t.Number(), t.String()], {
            description: "Items per page (default: 10)",
            examples: [10],
          })
        ),
        status: t.Optional(
          t.String({
            description: "Filter orders by status",
            examples: ["pending", "approved", "completed", "cancelled"],
          })
        ),
        orderBy: t.Optional(
          t.String({
            description: "Field to order by",
            examples: ["createdAt", "status", "total"],
          })
        ),
        orderDirection: t.Optional(
          t.String({
            description: "Order direction",
            examples: ["asc", "desc"],
          })
        ),
      }),
      detail: {
        summary: "Get user's orders",
        description:
          "Retrieves a paginated list of orders for the authenticated user. Supports filtering by status and ordering by createdAt, status, or total. Requires JWT token.",
        tags: ["orders"],
        operationId: "getUserOrders",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            orders: t.Array(
              t.Object({
                id: t.Number(),
                userId: t.Number(),
                status: t.String(),
                total: t.String(),
                createdAt: t.Date(),
                updatedAt: t.Date(),
                items: t.Array(
                  t.Object({
                    id: t.Number(),
                    productId: t.Number(),
                    quantity: t.Number(),
                    price: t.String(),
                    product: t.Union([
                      t.Object({
                        id: t.Number(),
                        name: t.String(),
                        slug: t.String(),
                        sku: t.String(),
                      }),
                      t.Null(),
                    ]),
                  })
                ),
              })
            ),
            pagination: t.Object({
              page: t.Number(),
              limit: t.Number(),
              total: t.Number(),
              totalPages: t.Number(),
            }),
          },
          { description: "Orders retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .get(
    "/orders/:id",
    async ({ jwt, headers, params }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const orderId = parseInt(params.id);

        const order = await db
          .select()
          .from(ordersTable)
          .where(
            and(eq(ordersTable.id, orderId), eq(ordersTable.userId, userId))
          )
          .limit(1);

        if (order.length === 0) {
          return status(404, { message: "Order not found" });
        }

        const orderItems = await db
          .select()
          .from(orderItemsTable)
          .where(eq(orderItemsTable.orderId, orderId));

        const itemsWithProducts = await Promise.all(
          orderItems.map(async (item) => {
            const product = await db
              .select()
              .from(productsTable)
              .where(eq(productsTable.id, item.productId))
              .limit(1);

            return {
              id: item.id,
              productId: item.productId,
              quantity: item.quantity,
              price: item.price,
              product: product[0]
                ? {
                    id: product[0].id,
                    name: product[0].name,
                    slug: product[0].slug,
                    sku: product[0].sku,
                    description: product[0].description,
                  }
                : null,
            };
          })
        );

        return {
          ...order[0],
          items: itemsWithProducts,
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        id: t.String({ description: "Order ID" }),
      }),
      detail: {
        summary: "Get order by ID",
        description:
          "Retrieves a specific order by its ID. The order must belong to the authenticated user. Requires JWT token.",
        tags: ["orders"],
        operationId: "getOrderById",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            id: t.Number(),
            userId: t.Number(),
            status: t.String(),
            total: t.String(),
            createdAt: t.Date(),
            updatedAt: t.Date(),
            items: t.Array(
              t.Object({
                id: t.Number(),
                productId: t.Number(),
                quantity: t.Number(),
                price: t.String(),
                product: t.Union([
                  t.Object({
                    id: t.Number(),
                    name: t.String(),
                    slug: t.String(),
                    sku: t.String(),
                    description: t.Union([t.String(), t.Null()]),
                  }),
                  t.Null(),
                ]),
              })
            ),
          },
          { description: "Order retrieved successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Order not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .patch(
    "/orders/:id",
    async ({ jwt, headers, params, body }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const orderId = parseInt(params.id);
        const { status: newStatus } = body;

        if (!newStatus || typeof newStatus !== "string") {
          return status(400, { message: "Status is required" });
        }

        const order = await db
          .select()
          .from(ordersTable)
          .where(
            and(eq(ordersTable.id, orderId), eq(ordersTable.userId, userId))
          )
          .limit(1);

        if (order.length === 0) {
          return status(404, { message: "Order not found" });
        }

        const currentOrder = order[0];
        const isApproving =
          newStatus.toLowerCase() === "approved" &&
          currentOrder.status.toLowerCase() !== "approved";

        if (isApproving) {
          const orderItems = await db
            .select()
            .from(orderItemsTable)
            .where(eq(orderItemsTable.orderId, orderId));

          for (const item of orderItems) {
            await db
              .update(productsTable)
              .set({
                stockCount: sql`${productsTable.stockCount} - ${item.quantity}`,
              })
              .where(eq(productsTable.id, item.productId));
          }
        }

        const [updatedOrder] = await db
          .update(ordersTable)
          .set({
            status: newStatus,
            updatedAt: new Date(),
          })
          .where(
            and(eq(ordersTable.id, orderId), eq(ordersTable.userId, userId))
          )
          .returning();

        return {
          id: updatedOrder.id,
          userId: updatedOrder.userId,
          status: updatedOrder.status,
          total: updatedOrder.total,
          createdAt: updatedOrder.createdAt,
          updatedAt: updatedOrder.updatedAt,
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        id: t.String({ description: "Order ID" }),
      }),
      body: t.Object({
        status: t.String({
          description: "New order status",
          examples: ["pending", "approved", "completed", "cancelled"],
        }),
      }),
      detail: {
        summary: "Update order status",
        description:
          "Updates the status of a specific order. The order must belong to the authenticated user. Requires JWT token.",
        tags: ["orders"],
        operationId: "updateOrderStatus",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            id: t.Number(),
            userId: t.Number(),
            status: t.String(),
            total: t.String(),
            createdAt: t.Date(),
            updatedAt: t.Date(),
          },
          { description: "Order status updated successfully" }
        ),
        400: t.Object(
          {
            message: t.String(),
          },
          { description: "Bad request - Missing or invalid status" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Order not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .delete(
    "/orders/:id",
    async ({ jwt, headers, params }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const orderId = parseInt(params.id);

        const order = await db
          .select()
          .from(ordersTable)
          .where(
            and(eq(ordersTable.id, orderId), eq(ordersTable.userId, userId))
          )
          .limit(1);

        if (order.length === 0) {
          return status(404, { message: "Order not found" });
        }

        await db
          .delete(ordersTable)
          .where(
            and(eq(ordersTable.id, orderId), eq(ordersTable.userId, userId))
          );

        return status(200, { message: "Order deleted successfully" });
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        id: t.String({ description: "Order ID" }),
      }),
      detail: {
        summary: "Delete order",
        description:
          "Deletes a specific order. The order must belong to the authenticated user. Order items will be automatically deleted due to cascade. Requires JWT token.",
        tags: ["orders"],
        operationId: "deleteOrder",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            message: t.String(),
          },
          { description: "Order deleted successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Order not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .patch(
    "/products/:id/stock",
    async ({ jwt, headers, params, body }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const productId = parseInt(params.id);
        const { action, amount } = body;

        if (!action || (action !== "increase" && action !== "decrease")) {
          return status(400, {
            message: "Action must be 'increase' or 'decrease'",
          });
        }

        if (
          !amount ||
          typeof amount !== "number" ||
          amount <= 0 ||
          !Number.isInteger(amount)
        ) {
          return status(400, { message: "Amount must be a positive integer" });
        }

        const product = await db
          .select()
          .from(productsTable)
          .where(
            and(
              eq(productsTable.id, productId),
              eq(productsTable.userId, userId)
            )
          )
          .limit(1);

        if (product.length === 0) {
          return status(404, { message: "Product not found" });
        }

        const currentStock = product[0].stockCount;
        const newStock =
          action === "increase"
            ? currentStock + amount
            : Math.max(0, currentStock - amount);

        const [updatedProduct] = await db
          .update(productsTable)
          .set({
            stockCount: newStock,
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(productsTable.id, productId),
              eq(productsTable.userId, userId)
            )
          )
          .returning();

        return {
          id: updatedProduct.id,
          stockCount: updatedProduct.stockCount,
          previousStockCount: currentStock,
          action,
          amount,
        };
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        id: t.String({ description: "Product ID" }),
      }),
      body: t.Object({
        action: t.String({
          description: "Action to perform on stock",
          examples: ["increase", "decrease"],
        }),
        amount: t.Number({
          description: "Amount to increase or decrease",
          minimum: 1,
        }),
      }),
      detail: {
        summary: "Update product stock count",
        description:
          "Manually increases or decreases the stock count of a specific product. The product must belong to the authenticated user. Requires JWT token.",
        tags: ["products"],
        operationId: "updateProductStock",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            id: t.Number(),
            stockCount: t.Number(),
            previousStockCount: t.Number(),
            action: t.String(),
            amount: t.Number(),
          },
          { description: "Stock count updated successfully" }
        ),
        400: t.Object(
          {
            message: t.String(),
          },
          { description: "Bad request - Invalid action or amount" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Product not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .delete(
    "/products/:id",
    async ({ jwt, headers, params }) => {
      try {
        const authorization = headers.authorization;

        if (!authorization || !authorization.startsWith("Bearer ")) {
          return status(401, { message: "Unauthorized" });
        }

        const token = authorization.substring(7);
        const payload = await jwt.verify(token);

        if (!payload || typeof payload !== "object" || !("userId" in payload)) {
          return status(401, { message: "Unauthorized" });
        }

        const userId = payload.userId as number;
        const productId = parseInt(params.id);

        const product = await db
          .select()
          .from(productsTable)
          .where(
            and(
              eq(productsTable.id, productId),
              eq(productsTable.userId, userId)
            )
          )
          .limit(1);

        if (product.length === 0) {
          return status(404, { message: "Product not found" });
        }

        await db
          .delete(productsTable)
          .where(
            and(
              eq(productsTable.id, productId),
              eq(productsTable.userId, userId)
            )
          );

        return status(200, { message: "Product deleted successfully" });
      } catch (error) {
        console.error(error);
        return status(500, { message: "Internal server error" });
      }
    },
    {
      params: t.Object({
        id: t.String({ description: "Product ID" }),
      }),
      detail: {
        summary: "Delete product",
        description:
          "Deletes a specific product. The product must belong to the authenticated user. Product images and order items will be automatically deleted due to cascade. Requires JWT token.",
        tags: ["products"],
        operationId: "deleteProduct",
        security: [{ bearerAuth: [] }],
      },
      response: {
        200: t.Object(
          {
            message: t.String(),
          },
          { description: "Product deleted successfully" }
        ),
        401: t.Object(
          {
            message: t.String(),
          },
          { description: "Unauthorized - Invalid or missing JWT token" }
        ),
        404: t.Object(
          {
            message: t.String(),
          },
          { description: "Product not found" }
        ),
        500: t.Object(
          {
            message: t.String(),
          },
          { description: "Internal server error" }
        ),
      },
    }
  )
  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);
