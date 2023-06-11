
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;

namespace RSATest;

public class RSADotnetExample
{

    public static string GetPublicKeyXML(RSAParameters publicKey)
    {
        var writer = new StringWriter();
        var xmlS = new XmlSerializer(typeof(RSAParameters));
        xmlS.Serialize(writer, publicKey);
        return writer.ToString();
    }
    public static void Main()
    {
        var data = "DATA TO SIGN!";
        
        var rsa = RSA.Create();
        var privateKey = rsa.ExportParameters(true);
        var publicKey = rsa.ExportParameters(false);

        var dataBytes = Encoding.Unicode.GetBytes(data);
        rsa.ImportParameters(privateKey);
        var signature = rsa.SignData(dataBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        var signatureString = Convert.ToBase64String(signature);
        Console.WriteLine($"signature: \n {signatureString} \n");


        var publicKeyXMLString = RSADotnetExample.GetPublicKeyXML(publicKey);
        var dataBytesVerify = Encoding.Unicode.GetBytes(data);
        var signatureToBytes = Convert.FromBase64String(signatureString);

        // rsa.FromXmlString(publicKeyXMLString);
        // rsa.ImportParameters(publicKey);
        var valid = rsa.VerifyData(dataBytesVerify, signatureToBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        Console.WriteLine($"Valid: \n {valid} \n");

    }

}
