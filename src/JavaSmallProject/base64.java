package JavaSmallProject;

import sun.misc.BASE64Decoder;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * @author zhanghaosheng @shnu
 * @date 2022/2/8 15:14
 */

public class base64 {
    public static void main(String[] args){
        final Base64.Decoder decoder = Base64.getDecoder();
        final Base64.Encoder encoder = Base64.getEncoder();
        final String text = "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";
        final String text2 = "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";
        final String text3 = text.replaceAll("\\\n","");
        System.out.println(text3);
        //final byte[] textByte = text.getBytes(StandardCharsets.UTF_8);
        //encode
        //final String encodedText = encoder.encodeToString(textByte);
        //System.out.println(encodedText);
        //decode
        //System.out.println(new String(decoder.decode(encodedText)));
        base64.convertBase64ToFile(text3,"D:\\base64","base642.xlsx");
    }

    /**
     * 将base64字符串，生成文件
     */
    public static File convertBase64ToFile(String fileBase64String, String filePath, String fileName) {

        BufferedOutputStream bos = null;
        FileOutputStream fos = null;
        File file = null;
        try {
            File dir = new File(filePath);
            if (!dir.exists() && dir.isDirectory()) {//判断文件目录是否存在
                dir.mkdirs();
            }

            BASE64Decoder decoder = new BASE64Decoder();
            byte[] bfile = decoder.decodeBuffer(fileBase64String);

            file = new File(filePath + File.separator + fileName);
            fos = new FileOutputStream(file);
            bos = new BufferedOutputStream(fos);
            bos.write(bfile);
            return file;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }

}
