/**
 * @(#)PublicFuns.java
 * @author alexis
 * @version 1.0 2008-6-24
 * <p>
 * Copyright (C) 2000,2008 , KOAL, Inc.
 */

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SM3Digest;

/**
 *
 * Purpose:公用类
 *
 * @author alexis
 * @See
 * @since 1.0
 */

public class PublicFuns {
    private static Log log = LogFactory.getLog("PublicFuns");
    private static byte[] HEX_DECODE_CHAR = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,};

    /**
     * 填充字符串
     *
     * @param iniStr
     * @param fillStr
     * @param newStrLen
     * @param isLeft
     * @return
     * @date:2008-6-24
     */
    public static String fillString(String iniStr, String fillStr,
                                    int fillPostion, int newStrLen, boolean isLeft) {
        StringBuffer strBuf = new StringBuffer(iniStr);
        int iniStrlen = iniStr.getBytes().length;
        while (iniStrlen < newStrLen) {
            if (isLeft) {
                strBuf.insert(fillPostion, fillStr);
            } else {
                strBuf.append(fillStr);
            }
            iniStrlen++;
        }
        return strBuf.toString();
    }

    /**
     * 填充字符串
     *
     * @param iniStr
     * @param fillStr
     * @param newStrLen
     * @param isLeft
     * @return
     * @date:2008-6-24
     */
    public static String fillString(String iniStr, String fillStr,
                                    int newStrLen, boolean isLeft) {
        return fillString(iniStr, fillStr, 0, newStrLen, isLeft);
    }

    /**
     * 左填充数据
     *
     * @param iniStr
     * @param fillStr
     * @param newStrLen
     * @return
     * @date:2008-6-24
     */
    public static String leftFillStr(String iniStr, String fillStr,
                                     int newStrLen) {
        return fillString(iniStr, fillStr, newStrLen, true);
    }

    /**
     * 右填充数据
     *
     * @param iniStr
     * @param fillStr
     * @param newStrLen
     * @return
     * @date:2008-6-24
     */
    public static String rightFillStr(String iniStr, String fillStr,
                                      int newStrLen) {
        return fillString(iniStr, fillStr, newStrLen, false);
    }

    /**
     * To formate the date and to return the new String
     *
     * @param date
     * @param formateStr
     *            "yyyy/MM/dd" or "yyyyMMdd" and so on...
     * @return
     */
    public static String formatDate(Date date, String formateStr) {
        formateStr = formateStr.replaceAll("h", "H");
        SimpleDateFormat simpleDateFormate = new SimpleDateFormat(formateStr);
        return simpleDateFormate.format(date);
    }

    /**
     * 获取几天前的日期
     *
     * @param days
     * @return
     * @date:Nov 20, 2008
     */
    public static Date getAgoDate(int days) {
        Calendar now = Calendar.getInstance();
        now.add(Calendar.DAY_OF_YEAR, -days);
        return now.getTime();
    }

    // 234.0的格式转换为234
    public static String strKillPoint(String str) {
        String str2;
        if (str.indexOf(".") == -1) {
            str2 = str;
        } else {
            int j = str.indexOf(".");
            str2 = str.substring(0, j);
        }
        return str2;
    }

    /**
     * hash：对byte数组进行哈希运算
     *
     *
     * @return：哈希结果
     * @throws NoSuchAlgorithmException
     */
    public static byte[] hash(byte[] data) throws NoSuchAlgorithmException {
        byte[] digest = null;

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(data);
        digest = md.digest();

        return digest;
    }

    public static byte[] hashFile(String file) throws Exception {
        try {
            File fp = new File(file);

            int fileLen = (int) fp.length();
            byte[] buffTemp = new byte[fileLen];
            FileInputStream in = new FileInputStream(file);
            int iFileLeftLen = fileLen;
            int offset = 0;
            byte[] buff = new byte[2048];

            while (iFileLeftLen > 0) {
                int iRead = in.read(buff);
                System.arraycopy(buff, 0, buffTemp, offset, iRead);
                offset += iRead;
                iFileLeftLen -= iRead;
            }

            in.close();
            byte[] fileHash = hash(buffTemp);

            return fileHash;
        } catch (Exception e) {
            throw new Exception("HASH文件失败", e);
        }
    }

    /**
     * 对byte数组进行SHA256哈希运算
     *
     * @return：哈希结果
     * @throws NoSuchAlgorithmException
     */
    public static byte[] SHA256(byte[] in) {
        Digest sha = new SHA256Digest();
        sha.update(in, 0, in.length);
        byte[] result = new byte[sha.getDigestSize()];
        sha.doFinal(result, 0);
        return result;
    }

    /**
     * 对byte数组进行SHA1哈希运算
     *
     * @return：哈希结果
     * @throws NoSuchAlgorithmException
     */
    public static byte[] SHA1(byte[] in) {
        Digest sha = new SHA1Digest();
        sha.update(in, 0, in.length);
        byte[] result = new byte[sha.getDigestSize()];
        sha.doFinal(result, 0);
        return result;
    }

    /**
     * 对byte数组进行MD5哈希运算
     *
     *
     * @return：哈希结果
     * @throws NoSuchAlgorithmException
     */
    public static byte[] MD5(byte[] in) {
        Digest sha = new MD5Digest();
        sha.update(in, 0, in.length);
        byte[] result = new byte[sha.getDigestSize()];
        sha.doFinal(result, 0);
        return result;
    }

    /**
     * 对byte数组进行SM3哈希运算
     * @author fanyingbo
     *
     * @return：哈希结果
     * @throws NoSuchAlgorithmException
     */
    public static byte[] SM3(byte[] in) {
        Digest sha = new SM3Digest();
        sha.update(in, 0, in.length);
        byte[] result = new byte[sha.getDigestSize()];
        sha.doFinal(result, 0);
        return result;
    }

    /**
     * 对byte数组进行SHA512哈希运算
     * @author fanyingbo
     *
     * @return：哈希结果
     * @throws NoSuchAlgorithmException
     */
    public static byte[] SHA512(byte[] in) {
        Digest sha = new SHA512Digest();
        sha.update(in, 0, in.length);
        byte[] result = new byte[sha.getDigestSize()];
        sha.doFinal(result, 0);
        return result;
    }

    /**
     * 对byte数组进行SHA384哈希运算
     * @author fanyingbo
     *
     * @return：哈希结果
     * @throws NoSuchAlgorithmException
     */
    public static byte[] SHA384(byte[] in) {
        Digest sha = new SHA384Digest();
        sha.update(in, 0, in.length);
        byte[] result = new byte[sha.getDigestSize()];
        sha.doFinal(result, 0);
        return result;
    }

    /**
     * 对byte数组进行SHA224哈希运算
     * @author fanyingbo
     * @return：哈希结果
     * @throws NoSuchAlgorithmException
     */
    public static byte[] SHA224(byte[] in) {
        Digest sha = new SHA224Digest();
        sha.update(in, 0, in.length);
        byte[] result = new byte[sha.getDigestSize()];
        sha.doFinal(result, 0);
        return result;
    }

    /**
     * 格式化交易金额为报文传输格式
     *
     * @param dealMoney
     * @return
     * @date:Nov 18, 2008
     */
    public static String formateDealMoney(Double dealMoney) {
        String formateMoney = dealMoney.intValue() + "";
        formateMoney = formateMoney.substring(0, formateMoney.length() - 2)
                + "." + formateMoney.substring(formateMoney.length() - 2);
        return PublicFuns.rightFillStr(formateMoney, " ", 15);
    }

    /**
     * 整型转为BYTE数据，不足长度时前补0
     *
     * @param intdata
     * @param len
     * @return
     * @date:Nov 25, 2008
     */
    public static byte[] intToByte(int intdata, int len) {
        byte[] data = new byte[len];
        for (int i = 0; i < len; i++) {
            data[i] = (byte) ((intdata >> (len - 1 - i) * 8) & 0xFF);
        }
        return data;
    }

    public static final String bytesToHexString(byte[] bArray) {
        if (bArray == null) {
            return null;
        }

        StringBuffer sb = new StringBuffer(bArray.length);
        String sTemp;
        for (int i = 0; i < bArray.length; i++) {
            sTemp = Integer.toHexString(0xFF & bArray[i]);
            if (sTemp.length() < 2) {
                sb.append(0);
            }
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }


    public static final byte[] HexStringTobytes(String hex) {
        if (hex == null) {
            return null;
        }

        if (hex.trim().length() == 0) {
            return null;
        }

        byte[] bHex = hex.getBytes();
        byte[] b = new byte[bHex.length / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) (HEX_DECODE_CHAR[bHex[i * 2]] * 16 + HEX_DECODE_CHAR[bHex[i * 2 + 1]]);
        }
        return b;
    }


    /**
     *
     * byteToStr：将byte转换成16进制表示的字符串
     *
     * @param value：待转换的byte
     * @return String 转换后的字符串
     *
     * @see <参见的内容>
     */
    public static String byteToString(byte value) {
        return ("" + "0123456789ABCDEF".charAt(0xF & value >> 4) + "0123456789ABCDEF"
                .charAt(value & 0xF));
    }

    /**
     * 转换十六进制BYTE数据组为int
     *
     * @param data
     * @param begin
     * @param len
     * @return
     * @throws Exception
     * @date:Nov 25, 2008
     */
    public static int bytesToInt(byte[] data, int begin, int len)
            throws Exception {
        try {
            byte[] buffer;
            buffer = new byte[len];
            System.arraycopy(data, begin, buffer, 0, len);
            return (new BigInteger(1, buffer)).intValue();
        } catch (Exception e) {
            e.printStackTrace();
            throw new Exception("byte数组转换成整型失败！", e);
        }
    }

    /**
     * 转换十六进制BYTE数据组为long
     *
     * @param data
     * @param begin
     * @param len
     * @return
     * @throws Exception
     * @date:Nov 25, 2008
     */
    public static long bytesToLong(byte[] data, int begin, int len)
            throws Exception {
        try {
            byte[] buffer;
            buffer = new byte[len];
            System.arraycopy(data, begin, buffer, 0, len);
            return (new BigInteger(1, buffer)).longValue();
        } catch (Exception e) {
            throw new Exception("byte数组转换成整型失败！", e);
        }
    }

    public static String trace(byte[] b) {
        StringBuffer c = new StringBuffer();
        for (int i = 0; i < b.length; i++) {
            String hexString = Integer.toHexString(b[i] & 0XFF).toUpperCase();
            if (hexString.length() == 1) {
                c.append("0");
                c.append(hexString);
            } else {
                c.append(hexString);
            }
            c.append(" ");
        }
        return c.toString();
    }

    /**
     * 运行外部进程
     * @param cmdStr
     * @return
     */
    public static int runOutProcess(String cmdStr, String... path) throws Exception {
        log.info("执行命令：" + cmdStr);
        String[] listCmd = cmdStr.split(" ");
        ProcessBuilder pb = new ProcessBuilder(listCmd);
        if (path != null && path.length > 0) {
            log.info("运行路径：" + path[0]);
            pb.directory(new File(path[0]));
        }
        pb.redirectErrorStream(true);
        final Process process = pb.start();
        log.info("============外部程序开始执行============");
        /* 
        * 以下代码用于获取外部程序的console的信息获取，由于外部程序都有自己的日志，因此无需此处再捕获打印
        * 注释以下代码，防止日志重复记录
        new Thread(new Runnable() {
			public void run() {
				BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream())); 
				try{
					String line = null ;
					while((line = br.readLine()) != null){
						// log.info("================="+line);
					}
				}catch (IOException e){
					log.error("读取输出流错误："+e.getMessage());
				}
			}
        }).start();
        */

        process.waitFor();
        int ret = process.exitValue();
        log.info("============外部程序执行成功, 返回:[" + ret + "]============");
        return ret;
    }

    public static String getAppRoot(String appRoot) {
        if (!(appRoot.endsWith("/") || appRoot.endsWith("\\"))) {
            appRoot = appRoot + "/";
        }
        return appRoot;
    }

    public static byte[] setTLV(String tag, int len, byte[] value) {
        int tagDataLen = 2 + 2 + len;
        byte[] tagValue = new byte[tagDataLen];

        // tag
        byte[] tagByte = PublicFuns.HexStringTobytes(tag);
        //length
        byte[] lenByte = PublicFuns.HexStringTobytes(String.format("%04X", len));
        int offset = 0;
        System.arraycopy(tagByte, 0, tagValue, offset, tagByte.length);
        offset += tagByte.length;
        System.arraycopy(lenByte, 0, tagValue, offset, lenByte.length);
        offset += lenByte.length;
        System.arraycopy(value, 0, tagValue, offset, len);
        return tagValue;
    }

    /**
     * 获取分段数据列表中的指定字段值
     * 例如"1|2|3", getItem(line, 0, "\\|")可以获取到1
     *
     * @param line 待解析的数据列表数据
     * @param pos 指定的字段序号0-sn
     * @param sep 分隔符
     * @return 解析得到的字段值
     */
    public static String getItem(String line, int pos, String sep) {
        if (line == null || sep == null)
            return null;

        String tmp = null;

        String[] tmpList = line.split(sep);

        if (pos >= tmpList.length) {
            return null;
        }

        tmp = tmpList[pos];
        return tmp;
    }

    /**
     * 用于根据路径获取XML报文的字段
     *
     * @param src 待解析的XML报文
     * @param path 待获取的字段相对路径，必须以"/"开头，并分割字段路径，例如"/root/first/second"
     * @return 解析得到的字段值
     */
    public static String GetValueByPath(String src, String path) {
        if (src == null || path == null) {
            return null;
        }

        String szTemp = src;
        String szTag;
        /* 找到第一个头 */
        szTag = getItem(path, 1, "/");
        int iSn = 1;

        while (szTag != null) {
            szTemp = GetValueByTag(szTemp, szTag);
            if (szTemp == null) {
                return null;
            }

            iSn++;
            szTag = getItem(path, iSn, "/");
        }

        return szTemp;
    }

    /**
     * 根据TAG获取XML域中的值
     *
     * @param src 待解析的XML报文
     * @param tag 待获取的字段名
     * @return 解析得到的字段值
     */
    public static String GetValueByTag(String src, String tag) {
        if (src == null || tag == null) {
            return null;
        }

        String szTagHead = "<" + tag + ">";
        String szTagEnd = "</" + tag + ">";

        /* 找到<tag>标签头 */
        int nIdx1 = src.indexOf(szTagHead);
        if (nIdx1 < 0) {
            return null;
        }

        /* 找到</tag>标签尾 */
        int nIdx2 = src.indexOf(szTagEnd);
        if (nIdx2 < 0) {
            return null;
        }

        nIdx1 += szTagHead.length();
        String value = src.substring(nIdx1, nIdx2).trim();

        if (value.length() == 0) {
            return null;
        }

        return value;
    }

    public static String getObjValue(Object obj) {
        if (obj == null) {
            return "";
        }

        return obj.toString();
    }

    public static int getObjIntValue(Object obj) {
        if (obj == null) {
            return -1;
        }
        if (isNumber(obj.toString())) {
            return Integer.parseInt(obj.toString());
        } else {
            return -1;
        }
    }

    /*
     * 新增，便于读取TB_CUPS_APP_KEY表中，PIK_OP_DATE和MAK_OP_DATE两个字段，用于申请PIK/MAK和申请PIK和MAK两个服务
     * by:zhangrui
     * 2017/7/17
     */
    public static Date getObjDateValue(Object obj) {
        if (obj == null) {
            return null;
        }
        return (Date) obj;
    }


    /**
     * byte数组异或
     * @param byt1
     * @param byt2
     * @return
     */
    public static byte[] xor(byte[] byt1, byte[] byt2) {
        int len = Math.max(byt1.length, byt2.length);
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = (byte) (byt1[i] ^ byt2[i]);
        }
        return result;
    }

    /**
     * 验证字符串是否为数字的字符串
     * 支持前面有正负号
     * @param str
     * @return true-是数字形式的字符串，false-不是数字形式字符串
     */
    public static boolean isNumber(String str) {
        if (str.matches("^(\\+|-)?\\d+"))
            return true;
        else
            return false;
    }

    public static boolean isHex(String str) {
        String hexReg = "\\p{XDigit}+";
        if (str.matches(hexReg)) {
            return true;
        } else {
            return false;
        }
    }
}

/**
 * Revision history
 * -------------------------------------------------------------------------
 *
 * Date Author Note
 * -------------------------------------------------------------------------
 * 2008-6-24 alexis 创建版本
 * 2016-12-22 linzf 增加XML解析方法并整理文件
 */
