import { describe, expect, it } from "vitest";
import { mailPath, parseMailPath, routeForSegment } from "./routes";

describe("mail routes", () => {
  it("uses /oauth as the public login route", () => {
    expect(parseMailPath("/mail/oauth", "/mail/")).toMatchObject({
      segment: "oauth",
      page: "login",
      known: true,
    });
    expect(mailPath("oauth", "/mail/")).toBe("/mail/oauth");
  });

  it("keeps Microsoft mailbox authorization on its own main-app tab", () => {
    expect(routeForSegment("microsoft-oauth")).toMatchObject({
      segment: "microsoft-oauth",
      page: "oauth",
      known: true,
    });
    expect(mailPath("microsoft-oauth", "/mail/")).toBe("/mail/microsoft-oauth");
  });

  it("keeps API key management on its own admin-group tab", () => {
    expect(routeForSegment("api-keys")).toMatchObject({
      segment: "api-keys",
      page: "api-keys",
      known: true,
    });
    expect(mailPath("api-keys", "/mail/")).toBe("/mail/api-keys");
  });
});
