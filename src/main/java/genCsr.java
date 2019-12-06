import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;
import sun.security.tools.keytool.CertAndKeyGen;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.PrintStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class genCsr {

    @Test
    public void genCsr() throws Exception {
        String signalg="";

        String alg = "RSA1024";
        String subject = "cert";
        String provider = "0000";

        int alglength=0;
        String keyAlg="";
        if(alg.toUpperCase().equals("RSA1024")){
            signalg="SHA1WithRSA";
            alglength=1024;
            keyAlg="RSA";
        }else if(alg.toUpperCase().equals("RSA2048")){
            signalg="SHA1WithRSA";
            alglength=2048;
            keyAlg="RSA";
        }else if(alg.toUpperCase().equals("SM2")){
            signalg="SM3withSM2";
            alglength=256;
            keyAlg="SM2";
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlg);
        keyGen.initialize(alglength);
        KeyPair kp = keyGen.generateKeyPair();
        PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(new X500Name(subject), SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(signalg);
        jcaContentSignerBuilder.setProvider(provider);
        ContentSigner contentSigner = jcaContentSignerBuilder.build(kp.getPrivate());
        builder.build(contentSigner);
        System.out.printf(builder.toString());
    }

    @Test
    public void genCsr2() throws Exception{
        String name = "CN";
        CertAndKeyGen gen = new CertAndKeyGen("RSA", "SHA1WithRSA");

        //生成1024位密钥
        gen.generate(1024);
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                // CN和公钥
                new X500Principal("CN = " + name), gen.getPublicKey());
        // 签名算法
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = null;
        signer = csBuilder.build(gen.getPrivateKey());
        // PKCS10的请求
        PKCS10CertificationRequest build = p10Builder.build(signer);
        System.out.printf(new String(Base64.encode(build.getEncoded())));
    }
    @Test
    public void genCsr3() throws Exception{

        Security.addProvider(new BouncyCastleProvider());

        String name = "CN";
//        String rsaPub = "MIIBCgKCAQEArhAiyzh2lMoVURY6tQvJB8WDs9Zorqg0ORCjrCXM3VcKX/3OpHVdmIPKgwVU+/K71PLjIxO+NPkXt4XNENgvUGpXD+he7Xnj1C03CYMM6kocUAy2oN8O8tFdetVbi82EeBNQoPy9blTPWz+O+05Zptc6nfb8vl4vZoltBi0s+rmSrERebDtycnkqbmC3UO2iHrvKEL7d+CEZGykyR0Ml3tp4CT/ZSRaew4hewyP1ZkNkVbIYUlER/veRGHZ0O6UJpQ2B2N+OCKwaKZ+ZYuwex6WtWunS5MXHYxgpTScR/0Y1O2V8Rg6kfDrbTAXlpchw2gn53zkgGbHdeyE17InGDwIDAQAB";
//        String rsaPri = "fjvWLsJ2j8C32/pOhs0m/MT0OLY6QlxqGKjlQEjQyf7vJIHsdo+3xK4kK6XpvZKdeSiyiaQ4jSNOrSOMGvU8iGNXkOxHdiBIWlC1SBY1c+C4eqR8GsLx3g21L8RWJsyHErbSF2WHMAsFNVVchmagSxOzQP4PNHnC3i58GAqZdfGDeAVhmXXLFjPHiseP6Z7YHEBZ0Cx+TEq/4Wkhm1Uo6gg6YDgXc00PJhyEhHqYHU3CsBWq6oPoK15xxTAmfgCZ+AGKu7FVS1/41Nz6zoHWCgsTnJQZAsDrD+ovHJyryzHdMKBKSmU8n4DIwJkeSaJjO+vm/P4af0VmUj+n1svmD5wOH9JvpIrg51W6pFE0CGiWU6q/xv5/pUDQIpZUYUtQA4EJrwIHfwUPQvXtiCXA21VVsNNo/MpzQjJSiE77cmkb8CazdRoGR9A7kHHNUYVdUNm1DpI5qcdliXUvhUlCa8gG28wwafIharsNEa+ANMFyTG5qDO0nkjqJJ/zyP5tCwZUrfOx5JQmkNdU6D87pDexv1h5TQpH8wUI0sA1D4BhrCdEGuVU1pIfP8ZvLlZ5eHk1v/noMBjUDRHhOaJVeHQF+ZVGdq6O/bMT/c0hgpp4NtLcppGqRS8bMqPe9Vm3lJqd5nBVH92+hs3UHWOgV6GsUSA5UaWWeWDTygEZZ3k6B3r63Mng6Kupvt21x/KGJmy04tu6orBYn0EjRTiD/D6DZnfHy0AlUV4cqM14pojHe6a3uKZ1cLQRVIFOva08eRIGAzLUI6rJ3Pa90or1IH0FFIC5yZDsizq/y6qfUIXh5PAjKUs0wOmztQb+TziQeOTCNmkW3WUSrnt7DEtC67gNvtlETUKMvuRgKkof/vXRjtHUmJE3DSOZyowZfedKGSSCiH2k30Ibo8Qz3h1tRkbwno9vc+efuNhw3G/HKevrFWphkdcmLwt1/F9zPfp2ukzV8jU4gaDxolhDD+/Jrz+8gc8fFVAygPZLlK7NOKKb88owiv9IrknxVa7tzPggF";

        String rsaPub = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsqlpBZjl6DD58do/q+hWxeGHhFKlSv/ZbEn57VP1vLONhwTD3TbmDo+XwURGXRH73RAjPQVez5otaIZy34GyFwWMdMszUtCIkcORf/oLWLyYxxlwUL11lUQbdhdIl1ttt+24oaEGoaVIB/Bk+20nUrFo+9yzrm4bRoSPIT1gEP9zYWgmKd77PNGeJ2aOj1aX+Bi5cZMnqZ80oPcxd5J3wHh9iyIYRoMvSd4xVRCiwITHbkcH8JWA1cGfnM4L/GzHZVNs1zVKG813sbAAXzVwNY7kfKCS/Hlrpy6nM+bQ7e44irfXVFhzD2vDNyBQ8/E4SOFgFK+XZJHlfnxuJ2sdRwIDAQAB";
        String rsaPri = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCyqWkFmOXoMPnx2j+r6FbF4YeEUqVK/9lsSfntU/W8s42HBMPdNuYOj5fBREZdEfvdECM9BV7Pmi1ohnLfgbIXBYx0yzNS0IiRw5F/+gtYvJjHGXBQvXWVRBt2F0iXW2237bihoQahpUgH8GT7bSdSsWj73LOubhtGhI8hPWAQ/3NhaCYp3vs80Z4nZo6PVpf4GLlxkyepnzSg9zF3knfAeH2LIhhGgy9J3jFVEKLAhMduRwfwlYDVwZ+czgv8bMdlU2zXNUobzXexsABfNXA1juR8oJL8eWunLqcz5tDt7jiKt9dUWHMPa8M3IFDz8ThI4WAUr5dkkeV+fG4nax1HAgMBAAECggEBAIoR4AaiVbJt/wsIBkK86Co+k3MQR4tBU+6a8NmXFAaDoDEi3pbbcUj5cWa7c8FDP6hka0ciGlZHqSXpGWdfHJksAZLU4lHytEgpog0L2K73+P2MzD6pW/BB1RMbBU9rKcyFmzTVc4GCcLsp7XBct5HxZteVhQqdLtj9YntmqhIXe9Yj1hIcd5uQg5GgLZrkIYPvr95rV+LAa6JqKw4bK0ObS8JtkvyfoGUHLVOeY9XSzFmZig6MtHz+Sg5F/SKPXJDfQrDrirQyntSWZRZW5Mu586Q0AiMekV80kQH742NQ7OKUs8eQd6Vk5W5N8nhMbZWBkqv7WCWeodts1AcMfcECgYEA7bOFyOM+crZm3o445Ne4DeOKQyrGGuU8QS3lHc3Ii1oY1ffvAWJvsLPhOFzijCTC7NWgI54cHfUMYytE/UBbtDooAT95UHemNlD8ZMU8kodl43yHznZk1QoHqzVpf8b/7M3Al5R5xiFOLmOiGfNAXwpATNdaPEcZElIdJRKIxacCgYEAwGpfJq51/DMD/OULRoATYRo03YLUCKWsW1zXbQ1mBHx1mta8w6vM3dYeMxvBdS8Qq1bBeH34W4Ev92j6THGCSXqjiOiPpKoqqsZrSdB9txNDcATIvI/nKk9sTU337fCBpsI6z9wSved3TSAvOQnYXv6cqqmMEPG3KSlqt3gvH2ECgYEAnawHgkm6kr0LX3VXp/Sv0gatIACviAenAFVBNZPbAxSwhL4BfBmfnMa1Dn4OiIeaBR9vKjEm1XhGz0FUcejO663n+2vvPMEhL8ZopS9wDoJhw5RHQVynZelRTPARGwEVoi6ZIfMLE7Hj+kF8tVn1yRUzscTnxjQjHVP6oSy6LOECgYBUBN7BnEKGupwOLNGMmlZb+z6ETyFZGUa2qkajJsuaP+J2lzfb1UPixiFvvbnu+nsz5fEbNR5ijnmsdhl9kb8LaNLJ8IrwoyF4aqXkmHacn3u+CUjCFbAiKIYpB1ewfWmPsJZPt1AzvkO42MnmBSeG63TrjJdNus542c3wiTlCYQKBgQCDeybbQEMLYr1FMAOaTx5PnTP1tJk/iY93wZKd1uY1379LzHt7xROzjp2AZukpso+TR+cfvat/D2FlE88kMIzb4JlsGFkiXms8g9zAJ3VTDLYwnyvE7qyjnUlvNmBuxZgPgv4F3+6jNkkUAkmEmH3KqwChuUeDelWwSHKysLZO5A==";

        X509EncodedKeySpec pubKey = new X509EncodedKeySpec(Base64.decode(rsaPub));
        KeyFactory rsa = KeyFactory.getInstance("RSA");
        PublicKey publicKey = rsa.generatePublic(pubKey);

        PKCS8EncodedKeySpec priKey = new PKCS8EncodedKeySpec(Base64.decode(rsaPri));
        PrivateKey privateKey = rsa.generatePrivate(priKey);

        X500Principal x500Principal = new X500Principal("CN = " + name);

        // 签名算法
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = null;
        signer = csBuilder.build(privateKey);
        byte[] signature = signer.getSignature();


        // PKCS10的请求
        CertificationRequestInfo crInfo = new CertificationRequestInfo(X500Name.getInstance(x500Principal.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), new DERSet());
        CertificationRequest cr = new CertificationRequest(crInfo, (new DefaultSignatureAlgorithmIdentifierFinder()).find("SHA256withRSA"), new DERBitString(signature));
        PKCS10CertificationRequest build = new PKCS10CertificationRequest(cr);
        StringBuilder sb = new StringBuilder().append("-----BEGIN CERTIFICATE REQUEST-----\n");
        sb.append(new String(Base64.encode(build.getEncoded())));
        sb.append("\n-----END CERTIFICATE REQUEST-----\n");
        System.out.printf(sb.toString());
    }

    @Test
    public void genCsr4() throws Exception {
        String pk="3081FF0281F900A5C91A87193D849F7A3939CEB144D9F0364092E166E7CBA56C89948FBFE00B77E3AE6A6E284992C7AC0AD03E574B596B6256023E70C196A7ED90FD306F4DC5AE817EA3522A5521B4558BAD52EE1BCAFBBA9101D808C3BE4DF497B11AE7D553CCFA7EDED855D78F34026887979CC5C163D0E7293D3AA6D5FAA1CFE1EFBEA19B55D5FF75B96F92661A933116213B4CBF7CD264763F40E5A614665BA742E78224134FA2C3C5A724554101B15D6203E779B5BD2FC3601C36A64BC97339BF5935E2BD44E08FF975DF8375C7788502B2BB7EC5A626CC981153705FC57D3AA13C07BF00849962E046BD211183965E5DC373759C760E286CB20AB847020103";
        String sk="387B80D39F96540C8DD45DB0075B6290F17E0E8DDF355D1473AC180AD09606F658323DF7A37E2D625FC75D99F179DB2DE9A054D299E782F5A028AEC2FFE09941FC01CC093E72C482C455928614F41ADEF2DDC075A6FBFF9C3791F2910B68B9DDBFF1604B0F34A4B8AD3E574908F88352284F58150DC629B7259F21DE57A8B2041DB37312BD392B08025E349F8FEE3EEA220F6DB0250CAA7B7AD03E9F51218F16432580F0D3B4A21A68EADA26E3D97F066E70969D6DFD76385C2226AE1C7FE57C9DCC36031ACC1CE333CDC4EE81FF5E24576FF437AFF668E11388DA6F3B0A79C60D262D2C397732D17626ED16717635B95EAC31166900A9320F6649155158675146F02039B7A384479281623668312374CF068BD672B4136D1F0CF14E597B42C07AFF6C0FD14770553F33A087A9432259F2FD7A914C8EA6C728D22B4BBE7D6CAEDEA7A38414D6F4C67757B8131C47A9D4215223BC93994418A2258EE98EB874B5EB413310AF3FCF990772E2F7F29F2C18AC5FA788EC53DE25585A558473217CAC1B7FEE8176B63D36CBAA7C838F35BF281C399BDE193B2FF826EC5BED3EB09D1942A239020ED7E30276E0FF0CAA4AEC0109165D95CC436433A8E172D781B816A7A190DC9299EF9C425EB750A6378D4B8ACD470E5345C9B04FF945AA674FF75B40CC1C47CB1083FCC9734D898D5CB059A79E6B089FEA29A525F71F7A743B6E32E4653D4F1DBE8A798100A5BD58479ECEA6F8DA2FD95F301FD5A98A76561E07FFC9BCF9876AAB668FDBE1372B0BB55CDC784BAB163237115A09BC781FD9FF3569CF1354D75615EDF7A7E043BD1D36357E984FA29988E0539D1995B74721B41D2507155DFA39BC9A7ACE2BE5E8122873D3EC968E412E887689793A5BF06F773A9B3B8E9C5EDCBE4F4F487EF978B430293B63D981EAA9E878315C1F8648CA9EB704171C7504F5ADAE485F785A7D836FC305C4870B3F4D87D71D6B72945AB63F9D89152DB28CFCAC2A4D6024C22307934DB144C8CEE86661F10625EEF4B1053A0AF9330528FAA6DD22E7B1CD071EDC60BFDB4730354CADEAEFED404D8F48069026ED2E9899CFA147196C2364EAB38859FB1C5909A97CDFB5AFC4E4853564335CB3A865D24796DF388FAE2EACDCA331646B6D1839D24679F13D7CCE300D524BBB1BCCA6A0564506DF7DFA5A9A0A9EFCEEA47C36C846CCDF7336BD69900CB28F848A5B200E435245D8E6D7345E5A658142DAE481F9C987748577D4FB66EB9CDE8B6A2560F344CA9865C0738B2B873A549F3E3D74EC574FC1B387127F64F5F47647A26DC8A479A5A62338468EE43A0320AB840DB060CBFD91DD70CEC469403571B9996C92CDF40FD5B09CF03B9CD3036E056010787EA46D78FCE524DDE38A39D1A72683A058013C5BEE00D3A696B27EF9F50785C33BC9A11844EA84B7D335EFC60315C2FBF9E42FCBEAEB3770319F95BBCB9DC37F29EBEB3D70A04E6B29AE28F671C1B8BEFA6225B652FEC5D08F1A15B5A518B29FA45C8234F1373CED2735573A96A576005F77C8BBFD2BEEA48D8A9A1502C43E0D165B4BEBE8F4544E6CC370221E5B7F3AD29BC78C8A9B328E50A4AC0A787FBEE04FBEFC5115C1FB32C3F59969D9E55F7EC488B9B3";
        String sign = "9BFC903397351781C631F815764DCC97E2D3F5A2DF477FED0D3821DC05013400709A1FF71FA086BF1D5C6902F58FD8671DADD31AD5DE06E0A1EE7F910939EDFD33AFEF8C6D065C9A6AE6973B49F9701845A3486839980FDD283FFDA9111C3461F1D0845F6128A02862DB824FCAEC32AA48710EC753DC418C8F530597A848E394733F8439C1A7BB789BD927A09B77E27DF7890767FA34B952D91495AC382736165E47AADC063CB95C1F3746CA8791D2EB71C4D2786F99892F00C5B595EE72E2E6A1B78AEF18482883708487BB0DC1301525F10BC06B99B8FF823E9A9995B00E08FE67EC4F39AFDF1F041D6E6157282860E61F8ED5C66CC2F1";
        Security.addProvider(new BouncyCastleProvider());
        // PKCS#1 --> PKCS#8
        RSAPublicKey pkcs = RSAPublicKey.getInstance(PublicFuns.HexStringTobytes(pk));

        RSAPublicKeySpec pubKey = new RSAPublicKeySpec(pkcs.getModulus(), pkcs.getPublicExponent());
        KeyFactory rsa = KeyFactory.getInstance("RSA");
        PublicKey publicKey = rsa.generatePublic(pubKey);

//        PKCS8EncodedKeySpec priKey = new PKCS8EncodedKeySpec(PublicFuns.HexStringTobytes(sk));
//        PrivateKey privateKey = rsa.generatePrivate(priKey);

        X500Principal x500Principal = new X500Principal("CN = CN");

        CertificationRequestInfo crInfo = new CertificationRequestInfo(X500Name.getInstance(x500Principal.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), new DERSet());
        CertificationRequest cr = new CertificationRequest(crInfo, (new DefaultSignatureAlgorithmIdentifierFinder()).find("SHA256withRSA"), new DERBitString(PublicFuns.HexStringTobytes(sign)));
        PKCS10CertificationRequest build = new PKCS10CertificationRequest(cr);
        StringBuilder sb = new StringBuilder().append("-----BEGIN CERTIFICATE REQUEST-----\n");
        sb.append(new String(Base64.encode(build.getEncoded())));
        sb.append("\n-----END CERTIFICATE REQUEST-----\n");
        System.out.printf(sb.toString());

    }

}
