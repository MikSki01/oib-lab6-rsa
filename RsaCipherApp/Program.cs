// ЛР6, завдання 1–2. Асиметричне шифрування RSA.
// Завдання 1: пара ключів зберігається у пам'яті.
// Завдання 2: пара ключів зберігається у контейнері. Іменовані контейнери CSP доступні лише у Windows,
// тому для кросплатформності роль контейнера виконує захищений файл із парою ключів (XML).
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

string message = "Таємне повідомлення для ЛР6 (RSA). Група МІТ-21.";
byte[] data = Encoding.UTF8.GetBytes(message);

// ---------- Завдання 1: ключі у пам'яті ----------
Console.WriteLine("=== Завдання 1. RSA, пара ключів у пам'яті ===\n");
using (var rsa = RSA.Create(2048))
{
    byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);   // шифрування відкритим ключем
    byte[] back = rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);   // розшифрування закритим ключем

    Console.WriteLine($"Відкритий текст: {message}");
    Console.WriteLine($"Розмір ключа: {rsa.KeySize} біт");
    Console.WriteLine($"Шифротекст (Base64, перші 64 символи): {Convert.ToBase64String(cipher)[..64]}…");
    Console.WriteLine($"Розшифровано: {Encoding.UTF8.GetString(back)}");
    Console.WriteLine($"Збіг з оригіналом: {(Encoding.UTF8.GetString(back) == message ? "так" : "ні")}\n");
}

// ---------- Завдання 2: ключі у контейнері (файлі) ----------
Console.WriteLine("=== Завдання 2. RSA, пара ключів у контейнері ===\n");
string container = Path.Combine(AppContext.BaseDirectory, "rsa-container.xml");

// Якщо контейнера ще немає — створюємо пару ключів і зберігаємо її у файл-контейнер.
if (!File.Exists(container))
{
    using var rsaNew = RSA.Create(2048);
    File.WriteAllText(container, rsaNew.ToXmlString(includePrivateParameters: true));
    Console.WriteLine($"Створено новий контейнер ключів: {Path.GetFileName(container)}");
}
else
{
    Console.WriteLine($"Використано наявний контейнер: {Path.GetFileName(container)}");
}

// Завантажуємо пару ключів із контейнера й шифруємо/розшифровуємо.
using (var rsa = RSA.Create())
{
    rsa.FromXmlString(File.ReadAllText(container));
    byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    byte[] back = rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);

    Console.WriteLine($"Відкритий текст: {message}");
    Console.WriteLine($"Шифротекст (Base64, перші 64 символи): {Convert.ToBase64String(cipher)[..64]}…");
    Console.WriteLine($"Розшифровано: {Encoding.UTF8.GetString(back)}");
    Console.WriteLine($"Збіг з оригіналом: {(Encoding.UTF8.GetString(back) == message ? "так" : "ні")}");
}

Console.WriteLine();
Console.WriteLine("Висновок: RSA — асиметричний шифр: відкритим ключем шифрують, а закритим розшифровують. На відміну");
Console.WriteLine("від зберігання в пам'яті (ключі зникають після завершення програми), контейнер дозволяє зберегти");
Console.WriteLine("пару ключів і повторно використовувати її. Іменовані контейнери CSP є лише у Windows, тому тут");
Console.WriteLine("роль контейнера виконує файл; на практиці закритий ключ треба додатково захищати (DPAPI, сховище ОС).");
