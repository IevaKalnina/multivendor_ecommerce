import { Webhook } from "svix";
import { headers } from "next/headers";
import { clerkClient, WebhookEvent } from "@clerk/nextjs/server";
import { User } from "@prisma/client";
import { db } from "@/lib/db";

export async function POST(req: Request) {
  const SIGNING_SECRET = process.env.SIGNING_SECRET;
  if (!SIGNING_SECRET) {
    throw new Error("Missing SIGNING_SECRET in .env");
  }

  // Create new Svix instance
  const wh = new Webhook(SIGNING_SECRET);

  // Get headers
  const headerPayload = headers();
  const svix_id = headerPayload.get("svix-id");
  const svix_timestamp = headerPayload.get("svix-timestamp");
  const svix_signature = headerPayload.get("svix-signature");
  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response("Error: Missing Svix headers", { status: 400 });
  }

  // Get body
  const payload = await req.json();
  const body = JSON.stringify(payload);

  // Verify
  let evt: WebhookEvent;
  try {
    evt = wh.verify(body, {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error("Error verifying webhook:", err);
    return new Response("Verification error", { status: 400 });
  }

  // Handle events
  if (evt.type === "user.created" || evt.type === "user.updated") {
    const data = payload.data;

    // Extract the role from Clerk's private metadata, defaulting to "USER" if not present.
    const role = data.private_metadata?.role || "USER";

    // Build a user object for Prisma including role
    const user: Partial<User> = {
      id: data.id,
      name: `${data.first_name} ${data.last_name}`,
      email: data.email_addresses[0]?.email_address,
      picture: data.image_url,
      role,
    };

    // Upsert into your DB: note that the update now includes role
    const dbUser = await db.user.upsert({
      where: { email: user.email },
      update: {
        name: user.name,
        picture: user.picture,
        role: user.role,
      },
      create: {
        id: user.id!,
        name: user.name!,
        email: user.email!,
        picture: user.picture!,
        role: user.role,
      },
    });

    const clerk = await clerkClient();

    // Update Clerk’s user metadata with the updated role from the database
    await clerk.users.updateUserMetadata(data.id, {
      privateMetadata: {
        role: dbUser.role,
      },
    });
  }

  if (evt.type === "user.deleted") {
    // Assuming the payload data includes an id property
    const userId = payload.data.id;
    await db.user.delete({
      where: {
        id: userId,
      },
    });
  }

  return new Response("Webhook received", { status: 200 });
}
