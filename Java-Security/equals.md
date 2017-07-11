# Java 的equals和==
## equals
equals是Object中的一个方法，也就是说所有的类都已经继承了equals方法。那么一般的equals方法是什么意思呢？先来试一试就知道了：
```
public class Yao{
  private int i = 1;

  public static void main(String[] args){
    Yao y1 = new Yao();
    Yao y2 = new Yao();
    if(y1.equals(y2)){
      System.out.println("y1 equals y2");
    }else{
      System.out.println("y1 不equals y2");
    }
  }
}
```
执行一下可以发现两个对象是不相等的。
