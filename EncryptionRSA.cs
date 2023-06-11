
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Serialization;

namespace RSATest;

public class AsymetricRSA
{
    private static RSACryptoServiceProvider _rsaProvider = new RSACryptoServiceProvider(2048);
    private readonly RSAParameters _privateKey;
    private readonly RSAParameters _publicKey;

    public AsymetricRSA()
    {
        _privateKey = _rsaProvider.ExportParameters(true);
        _publicKey = _rsaProvider.ExportParameters(false);
    }

    public string GetPublicKeyXML()
    {
        var writer = new StringWriter();
        var xmlS = new XmlSerializer(typeof(RSAParameters));
        xmlS.Serialize(writer, _publicKey);
        return writer.ToString();
    }

    public string RSAEncrypt(string dataToEncrypt)
    {
        try
        {
            _rsaProvider.ImportParameters(_publicKey);
            var toEncrypt = Encoding.Unicode.GetBytes(dataToEncrypt);
            var value = _rsaProvider.Encrypt(toEncrypt, false);
            return Convert.ToBase64String(value);
        }
        catch (Exception e)
        {
            return e.GetBaseException().ToString();
        }
    }

    public string RSADecrypt(string cypher)
    {
        try
        {
            _rsaProvider.ImportParameters(_privateKey);
            var toDecrypt = Convert.FromBase64String(cypher);
            var value = _rsaProvider.Decrypt(toDecrypt, false);
            return Encoding.Unicode.GetString(value);
        }
        catch (Exception e)
        {
            return e.GetBaseException().ToString();
        }
    }
}
