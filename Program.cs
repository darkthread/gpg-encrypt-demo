using System;
using System.Globalization;
using System.Text;
using System.IO;
using Libgpgme;
using System.Linq;

Context ctx = new Context();

// 如果要改用 Console.ReadLine() 輸入密碼：
// ctx.PinentryMode = PinentryMode.Loopback;
// ctx.SetPassphraseFunction(MyPassphraseCallback);
// PassphraseResult MyPassphraseCallback(Context ctx, PassphraseInfo info, ref char[] passwd)

if (ctx.Protocol != Protocol.OpenPGP)
    ctx.SetEngineInfo(Protocol.OpenPGP, null, null);

// 尋找名為 Jeffrey 的金鑰
const string SEARCHSTR = "Jeffrey";
// 取得第一把符合的金鑰
var key = ctx.KeyStore.GetKeyList(SEARCHSTR, false)?
    .OfType<PgpKey>() // 需為 PgpKey 型別
    // Uid 及 Fingerprint 不可為 null
    .Where(o => o.Uid != null && o.Fingerprint != null).FirstOrDefault();

if (key == null)
{
    Console.WriteLine("未找到金鑰");
    return;
}
Console.WriteLine($"找到金鑰 {key.Uid.Name} / {key.Fingerprint}");

Action<string, string> print = (message, title) => {
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"** {title} **");
    Console.ResetColor();
    Console.WriteLine(message);
};

var secrettext = "Hello, world!";
print(secrettext, "明文內容");

// 宣告記憶體緩衝區存放明文
var plain = new GpgmeMemoryData();
//plain.FileName = "my_document.txt";
// 建立 BinaryWriter 物件，以 UTF8 編碼寫入記憶體緩衝區
var binwriter = new BinaryWriter(plain, Encoding.UTF8);
binwriter.Write(secrettext.ToCharArray());
binwriter.Flush();
plain.Seek(0, SeekOrigin.Begin);

// 指定純文字輸出 (Armor)
ctx.Armor = true;

// 宣告記憶體緩衝區存放密文
var cipher = new GpgmeMemoryData();
//cipher.FileName = "my_document.txt";
ctx.Encrypt(new Key[] { key }, EncryptFlags.AlwaysTrust, plain, cipher);

// 顯示加密結果
cipher.Seek(0, SeekOrigin.Begin);
string encrypted;
using (var srEnc = new StreamReader(cipher, Encoding.UTF8)) {
    encrypted = srEnc.ReadToEnd();
    print(encrypted, "加密結果");
}

// 將密文串流指向開頭
var encData = new GpgmeMemoryData();
var encWriter = new BinaryWriter(encData, Encoding.UTF8);
encWriter.Write(encrypted.ToCharArray());
encData.Seek(0, SeekOrigin.Begin);

var decryptedData = new GpgmeMemoryData();
var decrst = ctx.Decrypt(encData, decryptedData);

// 讀取解密結果
decryptedData.Seek(0, SeekOrigin.Begin);
using var srDes = new StreamReader(decryptedData, Encoding.UTF8);
print(srDes.ReadToEnd(), "解密結果");

// 顯示加密金鑰資訊
Console.ForegroundColor = ConsoleColor.Cyan;
if (decrst.Recipients != null) 
    Console.WriteLine(
        string.Join("\n",
            decrst.Recipients!
            .Select(r => $"金鑰={r.KeyId} 加密演算法={Gpgme.GetPubkeyAlgoName(r.KeyAlgorithm)}").ToArray()));
Console.ResetColor();