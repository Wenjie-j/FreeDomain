"""Offline firewall4 start/stop transaction model; no router command runner.

An adapter used here is a test double. A target adapter must be written and
validated separately before packaging. The model deliberately has no CLI.
"""


def _result(action, state, steps, errors):
    return {"classification": "OFFLINE_TRANSACTION_MODEL_NOT_RUNTIME_BACKEND",
            "action": action, "state": state, "steps": steps, "errors": errors,
            "activation_approved": False}


def start(adapter):
    """Validate -> route -> rule -> include -> check -> reload, or compensate."""
    steps, errors = [], []
    route = rule = reload_attempted = stage_attempted = False
    try:
        blockers = adapter.preflight()
        steps.append("preflight")
        if blockers:
            return _result("start", "BLOCKED", steps, list(blockers))
        adapter.validate_candidate_offline()
        steps.append("validate_candidate_offline")
        adapter.add_local_route()
        route = True
        steps.append("add_local_route")
        adapter.add_masked_rule()
        rule = True
        steps.append("add_masked_rule")
        stage_attempted = True
        adapter.stage_include()
        steps.append("stage_include")
        adapter.fw4_check()
        steps.append("fw4_check")
        reload_attempted = True
        adapter.fw4_reload()
        steps.append("fw4_reload")
        adapter.verify_chains()
        steps.append("verify_chains")
        return _result("start", "MODEL_ACTIVE", steps, errors)
    except Exception as exc:
        errors.append("START_FAILED:" + type(exc).__name__)
        if not stage_attempted and not route and not rule:
            return _result("start", "BLOCKED", steps, errors)
        try:
            if stage_attempted:
                adapter.remove_include()
                steps.append("remove_include")
            if reload_attempted:
                adapter.fw4_reload()
                steps.append("rollback_fw4_reload")
        except Exception as rollback_exc:
            errors.append("FIREWALL_ROLLBACK_FAILED:" + type(rollback_exc).__name__)
            # Live firewall may still hold TPROXY. Keep local routing available.
            try:
                adapter.restore_include()
                steps.append("restore_include")
            except Exception as restore_exc:
                errors.append("INCLUDE_RESTORE_FAILED:" + type(restore_exc).__name__)
            state = ("MANUAL_RECOVERY_REQUIRED_KEEP_ROUTING" if route or rule
                     else "MANUAL_RECOVERY_REQUIRED")
            return _result("start", state, steps, errors)
        try:
            if rule:
                adapter.delete_masked_rule()
                steps.append("delete_masked_rule")
            if route:
                adapter.delete_local_route()
                steps.append("delete_local_route")
        except Exception as routing_exc:
            errors.append("ROUTING_ROLLBACK_FAILED:" + type(routing_exc).__name__)
            return _result("start", "MANUAL_RECOVERY_REQUIRED", steps, errors)
        return _result("start", "ROLLED_BACK", steps, errors)


def stop(adapter):
    """Remove rules first; drop local TPROXY route only after a good reload."""
    steps, errors = [], []
    owned = removed = False
    try:
        adapter.verify_ownership()
        owned = True
        steps.append("verify_ownership")
        removed = True
        adapter.remove_include()
        steps.append("remove_include")
        adapter.fw4_reload()
        steps.append("fw4_reload")
        adapter.verify_chains_absent()
        steps.append("verify_chains_absent")
    except Exception as exc:
        errors.append("STOP_FIREWALL_FAILED:" + type(exc).__name__)
        if not owned:
            return _result("stop", "BLOCKED_NOT_OWNED", steps, errors)
        if removed:
            try:
                adapter.restore_include()
                steps.append("restore_include")
            except Exception as restore_exc:
                errors.append("INCLUDE_RESTORE_FAILED:" + type(restore_exc).__name__)
        return _result("stop", "MANUAL_RECOVERY_REQUIRED_KEEP_ROUTING", steps, errors)
    try:
        adapter.delete_masked_rule()
        steps.append("delete_masked_rule")
        adapter.delete_local_route()
        steps.append("delete_local_route")
    except Exception as exc:
        errors.append("STOP_ROUTING_FAILED:" + type(exc).__name__)
        return _result("stop", "MANUAL_RECOVERY_REQUIRED", steps, errors)
    return _result("stop", "MODEL_INACTIVE", steps, errors)
