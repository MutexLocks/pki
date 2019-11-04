public class SyntaxTest {
    private static String str;

//    public SyntaxTest () {
//        System.out.println("Constructor");
//    }
//    static {
//        System.out.println("static");
//    }
    public static void main(String[] args) {
        // 计算S＝1＋2×3＋3×4＋4×5＋…＋N（N＋1），直到N（N＋1）项大于200为止。
        int n = 2;
        int sum = 0;
        while ((n * (n + 1)) <= 200) {
            sum = sum + n * (n + 1);
            n ++;
        }
        System.out.println(sum + 1 + "   n: " + n);
    }
}
enum Signal{GREEN, YELLOW, RED}

abstract class  a {


}

class b extends a {}
class c {
    String test() {
        try {
            int i = 1/ 0;
            return "aa";
        } catch (Exception e) {
            System.out.println("pp");
            return "bb";
        } finally {
            return "cc";
        }
    }
}