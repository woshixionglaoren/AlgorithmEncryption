package com.imooc.security.base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

public class Base64Demo {
    private static String test = "pokmppppppppppppppppppppppp";
    public static void main(String[] args) {
        BASE64Encoder base64Encoder = new BASE64Encoder();
        String encode = base64Encoder.encode(test.getBytes());
        System.out.println("encode = " + encode);

        BASE64Decoder base64Decoder = new BASE64Decoder();
        try {
            byte[] decodeBuffer = base64Decoder.decodeBuffer(encode);
            System.out.println("decodeBuffer = " + new String(decodeBuffer));
        } catch (IOException e) {
            e.printStackTrace();
        }
        
    }
}
