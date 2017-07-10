public class Equals{
    public static void main(String[] args){
        String s1 = "str";
        String s2 = "str";
        String s3 = new String("str");
        String s4 = new String("str");

        if(s1 == s2){
            System.out.println("s1 == s2 成立");
        }
        else{
            System.out.println("s1 == s2 不成立");
        }

        if(s1.equals(s2)){
            System.out.println("s1 equals s2 成立");
        }
        else{
            System.out.println("s1 equals s2 不成立");
        }


        if(s3 == s4){
            System.out.println("s3 == s4 成立");
        }
        else{
            System.out.println("s3 == s4 不成立");
        }

        if(s3.equals(s4)){
            System.out.println("s3 equals s4 成立");
        }
        else{
            System.out.println("s3 equals s4 不成立");
        }


        if(s1 == s3){
            System.out.println("s1 == s3 成立");
        }
        else{
            System.out.println("s1 == s3 不成立");
        }

        if(s1.equals(s3)){
            System.out.println("s1 equals s3 成立");
        }
        else{
            System.out.println("s1 equals s3 不成立");
        }

    }
}