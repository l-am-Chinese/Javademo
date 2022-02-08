package JavaSmallProject;

public class two {
    public static void main(String args[]) {
        int a, sum;     //表示100~999
        int i, j, k;//分别表示百位、十位、各位
        for (a = 100; a <= 999; a++) {
            i = a / 100;
            j = (a - i * 100) / 10;
            k = a - i * 100 - j * 10;
            sum = i * i * i + j * j * j + k * k * k;
            //java的运算符，立方要这样写，写成i^3这样，竟然运算不出来
            //如果遇到高次的话可以使用循环算出来
            if (sum == a) {
                System.out.println(sum);
            }

        }
    }
}