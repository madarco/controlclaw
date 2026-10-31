import { z } from "zod";

/** What an agent's permission request is about (the full list is documented in the console's requests.schema.ts). */
export const permissionKindSchema = z.enum(["payment", "delete", "access", "email_recipient", "app_call", "other", "exec", "plugin", "system", "settings_change", "meeting_request"]);
export type PermissionKind = z.infer<typeof permissionKindSchema>;
