// ABOUTME: 为类加载器恢复测试提供独立的真实 Android Java 进程。
// ABOUTME: 保持虚拟机存活，供测试脚本检查 Java 数组和加载失败路径。
package autel.test;

public final class StatusProbe {
    public static void main(String[] args) throws InterruptedException {
        System.out.println("TRACERPID_JAVA_READY");
        Thread.sleep(300000);
    }
}
