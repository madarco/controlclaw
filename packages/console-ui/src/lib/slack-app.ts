/**
 * What people need to build a Slack app that this platform can drive: the manifest they paste
 * into Slack, and the reading of a token that came back wrong.
 *
 * The manifest starts from OpenClaw's own "Minimal" Socket Mode manifest (its
 * `docs/channels/slack.md`), which is what the `@openclaw/slack` plugin expects: DMs, channel and
 * group history, mentions, the App Home tab, assistant threads and one slash command. On top of
 * that it asks for the scopes an agent needs to work in channels rather than only answer in them
 * — join and create channels, invite people, set a topic — for public channels (`channels:*`) and
 * private ones the app is in (`groups:*`), plus reading and leaving emoji reactions. It still
 * leaves out files, pins, group DMs and the emoji/usergroup reads.
 *
 * `reactions:read` covers the API read. Receiving a reaction as it happens would also need
 * `reaction_added` / `reaction_removed` under `bot_events`, which are not here: the
 * `@openclaw/slack` plugin does not subscribe to them.
 */

export const SLACK_APP_NEW_URL = "https://api.slack.com/apps/new";

export const SLACK_APP_MANIFEST = `{
  "display_information": {
    "name": "OpenClaw",
    "description": "Slack connector for OpenClaw"
  },
  "features": {
    "bot_user": { "display_name": "OpenClaw", "always_online": true },
    "app_home": {
      "home_tab_enabled": true,
      "messages_tab_enabled": true,
      "messages_tab_read_only_enabled": false
    },
    "assistant_view": {
      "assistant_description": "OpenClaw connects Slack assistant threads to OpenClaw agents.",
      "suggested_prompts": [
        { "title": "What can you do?", "message": "What can you help me with?" },
        { "title": "Draft a reply", "message": "Help me draft a reply." }
      ]
    },
    "slash_commands": [
      {
        "command": "/openclaw",
        "description": "Send a message to OpenClaw",
        "should_escape": false
      }
    ]
  },
  "oauth_config": {
    "scopes": {
      "bot": [
        "app_mentions:read",
        "assistant:write",
        "channels:history",
        "channels:join",
        "channels:manage",
        "channels:read",
        "channels:write.invites",
        "channels:write.topic",
        "chat:write",
        "commands",
        "groups:history",
        "groups:read",
        "groups:write",
        "groups:write.invites",
        "groups:write.topic",
        "im:history",
        "im:read",
        "im:write",
        "reactions:read",
        "reactions:write",
        "users:read"
      ]
    }
  },
  "settings": {
    "socket_mode_enabled": true,
    "event_subscriptions": {
      "bot_events": [
        "app_home_opened",
        "app_mention",
        "assistant_thread_context_changed",
        "assistant_thread_started",
        "message.channels",
        "message.groups",
        "message.im"
      ]
    }
  }
}`;

/**
 * Why a pasted token is not the one we need. Slack hands out four things that all look like
 * tokens, and three of them are the wrong one — so say which one arrived and where the right
 * one is, rather than "invalid token".
 */
export function slackTokenProblem(field: "bot" | "app", raw: string): string | null {
  const token = raw.trim();
  if (token === "") return null;
  const expected = field === "bot" ? "xoxb-" : "xapp-";
  if (token.startsWith(expected)) return null;

  // Token rotation. Slack cannot turn it off again, so a new app is the only way out.
  if (token.startsWith("xoxe.") || token.startsWith("xoxe-")) {
    return "This app has token rotation turned on, so its tokens expire after 12 hours. Slack can’t turn rotation off again. Create a new app from the manifest above and use its tokens.";
  }
  if (token.startsWith("xoxp-")) {
    return "That is a user token: it acts as you, not as the app. Add the scopes under Bot Token Scopes, reinstall the app, and copy the Bot User OAuth Token instead.";
  }
  if (field === "bot" && token.startsWith("xapp-")) return "That is the app-level token. The bot token belongs in the field above and starts with xoxb-.";
  if (field === "app" && token.startsWith("xoxb-")) return "That is the bot token. The app-level token comes from Basic Information → App-Level Tokens and starts with xapp-.";
  if (token.startsWith("xoxa-") || token.startsWith("xoxr-")) return "That is an OAuth code, not a token. Install the app to the workspace, then copy the Bot User OAuth Token.";
  return field === "bot"
    ? "A bot token starts with xoxb-. OAuth & Permissions → Bot User OAuth Token, after the app is installed."
    : "An app-level token starts with xapp-. Basic Information → App-Level Tokens, with the connections:write scope.";
}
