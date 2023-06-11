using System.Security.Cryptography;
using System.Text;

public class SignatureRSA
{

    public static string SignData(string data, RSAParameters privateKey)
    {
        byte[] signedBytes;

        var toEncrypt = Encoding.Unicode.GetBytes(data);
        var rsa = new RSACryptoServiceProvider(2048);
        try
        {
            //// Import the private key used for signing the message
            rsa.ImportParameters(privateKey);

            //// Sign the data, using SHA512 as the hashing algorithm
            signedBytes = rsa.SignData(toEncrypt, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
            return "error";
        }
        finally
        {
            //// Set the keycontainer to be cleared when rsa is garbage collected.
            rsa.PersistKeyInCsp = false;
        }

        //// Convert the a base64 string before returning
        return Convert.ToBase64String(signedBytes);
    }

    public static bool VerifyData(string data, string signedData, RSAParameters publicKey)
    {
        var success = false;
        var bytesToVerify = Encoding.Unicode.GetBytes(data);
        var signedBytes = Encoding.Unicode.GetBytes(signedData);
        var rsa = new RSACryptoServiceProvider(2048);
        try
        {
            rsa.ImportParameters(publicKey);
            success = rsa.VerifyData(bytesToVerify, CryptoConfig.MapNameToOID("SHA512")!, signedBytes);
        }
        catch (CryptographicException e)
        {
            Console.WriteLine(e.Message);
        }
        finally
        {
            rsa.PersistKeyInCsp = false;
        }

        return success;
    }
}
