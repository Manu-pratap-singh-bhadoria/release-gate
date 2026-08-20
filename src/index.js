const HEX40 = /^[0-9a-f]{40}$/;

function evaluatePolicy(body) {
  const violations = [];

  const workflow = body.workflow ?? {};
  const image = body.image ?? {};

  // Permissions must be exactly:
  // contents: read
  // packages: write
  // id-token: none
  const permissions = workflow.permissions ?? {};

  if (
    Object.keys(permissions).length !== 3 ||
    permissions.contents !== "read" ||
    permissions.packages !== "write" ||
    permissions["id-token"] !== "none"
  ) {
    violations.push("EXCESS_PERMISSION");
  }

  // pull_request_target is never allowed
  if (workflow.trigger === "pull_request_target") {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // Tests must pass, matrix must finish, failFast must be false
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push("TESTS_INCOMPLETE");
  }

  // Third-party actions must use a 40-character lowercase SHA.
  // actions/* may use a version tag.
  const actions = Array.isArray(workflow.actions)
    ? workflow.actions
    : [];

  for (const action of actions) {
    if (!action || typeof action !== "object") {
      violations.push("MUTABLE_ACTION");
      continue;
    }

    const owner = action.owner;
    const ref = String(action.ref ?? "");

    if (owner !== "actions" && !HEX40.test(ref)) {
      violations.push("MUTABLE_ACTION");
    }
  }

  // Image must be multi-stage
  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }

  // Image must run as non-root
  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }

  // Secrets: none or buildkit are allowed
  if (
    image.secretMode !== "none" &&
    image.secretMode !== "buildkit"
  ) {
    violations.push("SECRET_IN_LAYER");
  }

  // No critical vulnerabilities
  if (image.criticalVulnerabilities !== 0) {
    violations.push("CRITICAL_CVE");
  }

  // Image must be digest pinned
  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }

  // Production requirements
  if (body.target === "production") {
    if (
      workflow.trigger !== "push" ||
      body.ref !== "refs/heads/main"
    ) {
      violations.push("INVALID_PRODUCTION_REF");
    }

    if (workflow.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations,
  };
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (
      request.method !== "POST" ||
      url.pathname !== "/release-gate"
    ) {
      return new Response(
        JSON.stringify({
          error: "POST /release-gate required",
        }),
        {
          status: 404,
          headers: {
            "content-type": "application/json",
          },
        }
      );
    }

    try {
      const body = await request.json();
      const result = evaluatePolicy(body);

      return new Response(JSON.stringify(result), {
        status: 200,
        headers: {
          "content-type": "application/json",
        },
      });
    } catch {
      return new Response(
        JSON.stringify({
          decision: "block",
          violations: ["TESTS_INCOMPLETE"],
        }),
        {
          status: 400,
          headers: {
            "content-type": "application/json",
          },
        }
      );
    }
  },
};