"""Offline OpenClash/Sing-box backend switch model; contains no command runner."""


BACKENDS = {"disabled", "sing-box", "openclash"}


def _result(target, state, steps, errors, previous=None):
    return {
        "classification": "OFFLINE_PROXY_SWITCH_MODEL_NOT_RUNTIME_APPROVAL",
        "target": target,
        "previous": previous,
        "state": state,
        "steps": steps,
        "errors": errors,
        "activation_approved": False,
    }


def switch(adapter, target):
    """Switch one exclusive backend in a simulation, with checked rollback.

    Adapter verification methods must raise on failed checks. snapshot_state()
    and restore_snapshot() cover configuration and the persisted backend choice;
    service state is inspected separately, including after partial command errors.
    A real implementation still requires an exclusive transaction lock and
    durable recovery state; this model has neither a command runner nor a lock.
    """
    steps, errors = [], []
    if target not in BACKENDS:
        return _result(target, "BLOCKED_INVALID_TARGET", steps,
                       ["INVALID_TARGET"])
    try:
        active = set(adapter.active_backends())
        steps.append("active_backends")
    except Exception as exc:
        return _result(target, "BLOCKED_INSPECTION_FAILED", steps,
                       ["INSPECTION_FAILED:" + type(exc).__name__])
    if not active.issubset(BACKENDS - {"disabled"}) or len(active) > 1:
        return _result(target, "MANUAL_RECOVERY_REQUIRED_MULTIPLE_ACTIVE", steps,
                       ["BACKEND_EXCLUSIVITY_VIOLATED"])
    previous = next(iter(active), "disabled")
    if previous == target:
        try:
            if target != "disabled":
                adapter.verify_backend(target)
                steps.append("verify_backend")
                adapter.verify_management_reachable()
                steps.append("verify_management_reachable")
                adapter.verify_domestic_direct_path(target)
                steps.append("verify_domestic_direct_path")
            return _result(target, "MODEL_UNCHANGED", steps, errors, previous)
        except Exception as exc:
            errors.append("CURRENT_BACKEND_UNHEALTHY:" + type(exc).__name__)
            return _result(target, "BLOCKED_CURRENT_BACKEND_UNHEALTHY",
                           steps, errors, previous)
    try:
        adapter.validate_target(target)
        steps.append("validate_target")
        adapter.snapshot_state()
        steps.append("snapshot_state")
    except Exception as exc:
        errors.append("PRE_SWITCH_FAILED:" + type(exc).__name__)
        return _result(target, "BLOCKED_PRE_SWITCH", steps, errors, previous)
    # Commands may change service state before raising an error.
    target_start_attempted = False
    try:
        if previous != "disabled":
            adapter.stop_backend(previous)
            steps.append("stop_previous")
            adapter.verify_backend_inactive(previous)
            steps.append("verify_previous_inactive")
        if target != "disabled":
            target_start_attempted = True
            adapter.start_backend(target)
            steps.append("start_target")
            adapter.verify_backend(target)
            steps.append("verify_backend")
            if set(adapter.active_backends()) != {target}:
                raise RuntimeError("backend exclusivity check failed")
            steps.append("verify_exclusive")
            adapter.verify_management_reachable()
            steps.append("verify_management_reachable")
            adapter.verify_domestic_direct_path(target)
            steps.append("verify_domestic_direct_path")
        else:
            if set(adapter.active_backends()):
                raise RuntimeError("backend remained active")
            steps.append("verify_all_inactive")
            adapter.verify_management_reachable()
            steps.append("verify_management_reachable")
        adapter.commit_choice(target)
        steps.append("commit_choice")
        return _result(target, "MODEL_SWITCHED", steps, errors, previous)
    except Exception as exc:
        errors.append("SWITCH_FAILED:" + type(exc).__name__)
        try:
            if target_start_attempted:
                adapter.stop_backend(target)
                steps.append("stop_failed_target")
                adapter.verify_backend_inactive(target)
                steps.append("verify_failed_target_inactive")
            allowed = {previous} if previous != "disabled" else set()
            if not set(adapter.active_backends()).issubset(allowed):
                raise RuntimeError("unexpected active backend before restore")
            adapter.restore_snapshot()
            steps.append("restore_snapshot")
            restored_active = set(adapter.active_backends())
            if not restored_active.issubset(allowed):
                raise RuntimeError("unexpected active backend after snapshot restore")
            if previous != "disabled":
                if not restored_active:
                    adapter.start_backend(previous)
                    steps.append("restart_previous")
                adapter.verify_backend(previous)
                steps.append("verify_restored_backend")
            if set(adapter.active_backends()) != allowed:
                raise RuntimeError("restored backend exclusivity check failed")
            steps.append("verify_restored_exclusive")
            adapter.verify_management_reachable()
            steps.append("verify_restored_management")
            if previous != "disabled":
                adapter.verify_domestic_direct_path(previous)
                steps.append("verify_restored_domestic_direct_path")
            return _result(target, "ROLLED_BACK", steps, errors, previous)
        except Exception as rollback_exc:
            errors.append("ROLLBACK_FAILED:" + type(rollback_exc).__name__)
            return _result(target, "MANUAL_RECOVERY_REQUIRED", steps,
                           errors, previous)
