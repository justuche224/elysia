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
} from "./db/schema";
import { eq, and, desc, sql, or } from "drizzle-orm";
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

        const products = await db
          .select()
          .from(productsTable)
          .where(eq(productsTable.userId, userId))
          .orderBy(desc(productsTable.createdAt))
          .limit(limit)
          .offset(offset);

        const totalCountResult = await db
          .select({ count: sql<number>`count(*)` })
          .from(productsTable)
          .where(eq(productsTable.userId, userId));

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
      }),
      detail: {
        summary: "Get user's products",
        description:
          "Retrieves a paginated list of products for the authenticated user. Requires JWT token.",
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
  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);
