use crate::engine::request::PacketRequest;
use crate::rules::error::RuleError;
use crate::util::sync::LockResultExt;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use tokio::runtime::{Builder, Handle, Runtime};

type Result<T> = std::result::Result<T, RuleError>;

pub type TestSendHook = Option<Arc<dyn Fn(String, PacketRequest) -> Result<()> + Send + Sync>>;

pub static SEND_HOOK: LazyLock<Mutex<TestSendHook>> = LazyLock::new(|| Mutex::new(None));
static EXECUTOR_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static TEST_RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("create rule executor test runtime")
});

pub struct ExecutorTestGuard {
    _guard: MutexGuard<'static, ()>,
}

impl Drop for ExecutorTestGuard {
    fn drop(&mut self) {
        clear_send_hook();
    }
}

pub struct SendHookGuard;

impl Drop for SendHookGuard {
    fn drop(&mut self) {
        clear_send_hook();
    }
}

pub fn executor_lock() -> ExecutorTestGuard {
    let guard = EXECUTOR_LOCK.lock().ignore_poison();
    clear_send_hook();
    ExecutorTestGuard { _guard: guard }
}

pub fn send_hook_guard(hook: TestSendHook) -> SendHookGuard {
    clear_send_hook();
    set_send_hook(hook);
    SendHookGuard
}

pub fn send_hook() -> TestSendHook {
    SEND_HOOK.lock().ignore_poison().clone()
}

pub fn set_send_hook(hook: TestSendHook) {
    *SEND_HOOK.lock().ignore_poison() = hook;
}

pub fn clear_send_hook() {
    *SEND_HOOK.lock().ignore_poison() = None;
}

pub fn runtime_handle() -> Handle {
    TEST_RUNTIME.handle().clone()
}
