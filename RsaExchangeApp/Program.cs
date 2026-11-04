// ЛР6, завдання 3–4. Обмін зашифрованими повідомленнями за допомогою файлів відкритих ключів.
// Завдання 3: збереження відкритого ключа у файлі та шифрування повідомлень відкритими ключами інших.
// Завдання 4: генерація відкритого ключа RSA 2048 біт, збереження у файл <прізвище>.xml, обмін вітаннями.
//
// Відкритий ключ (public-only XML) можна вільно поширювати: ним інші шифрують повідомлення для власника.
// Розшифрувати їх може лише власник своїм закритим ключем.
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

string dir = AppContext.BaseDirectory;
var pad = RSAEncryptionPadding.OaepSHA256;

Console.WriteLine("=== RSA: обмін повідомленнями через файли відкритих ключів ===\n");

// Власник (я). Генеруємо пару ключів і зберігаємо ВІДКРИТИЙ ключ у файл з транслітерацією прізвища.
using var me = RSA.Create(2048);
string myPublicFile = Path.Combine(dir, "Skorokhod.xml");          // транслітерація прізвища
File.WriteAllText(myPublicFile, me.ToXmlString(includePrivateParameters: false)); // лише відкритий ключ
Console.WriteLine($"Згенеровано ключ RSA {me.KeySize} біт. Відкритий ключ збережено у файл: {Path.GetFileName(myPublicFile)}");
Console.WriteLine("(файл містить лише відкритий ключ — його можна поширювати у чаті)\n");

// Імітація двох інших студентів зі своїми парами ключів та файлами відкритих ключів.
var studentA = RSA.Create(2048);
var studentB = RSA.Create(2048);
string pubA = Path.Combine(dir, "StudentA.xml");
string pubB = Path.Combine(dir, "StudentB.xml");
File.WriteAllText(pubA, studentA.ToXmlString(false));
File.WriteAllText(pubB, studentB.ToXmlString(false));

// Завдання 4: шифруємо вітання двом наступним за списком студентам їхніми відкритими ключами.
Console.WriteLine("--- Надсилання вітань (шифрування відкритими ключами одержувачів) ---");
SendGreeting("Студент А", pubA, "Вітаю, Студенте А! З повагою, Скороход.");
SendGreeting("Студент Б", pubB, "Вітаю, Студенте Б! Гарного дня. Скороход.");

// Отримані від інших вітання: інші шифрують МОЇМ відкритим ключем, я розшифровую своїм закритим.
Console.WriteLine("\n--- Отримання вітань (розшифрування власним закритим ключем) ---");
byte[] fromA = EncryptWithPublicFile(myPublicFile, "Вітаю, Скороходе! Від Студента А.");
byte[] fromB = EncryptWithPublicFile(myPublicFile, "Доброго дня, Скороходе! Студент Б.");
Console.WriteLine($"Від Студента А: {Encoding.UTF8.GetString(me.Decrypt(fromA, pad))}");
Console.WriteLine($"Від Студента Б: {Encoding.UTF8.GetString(me.Decrypt(fromB, pad))}");

Console.WriteLine();
Console.WriteLine("Висновок: відкритий ключ вільно поширюється файлом (*.xml) і служить лише для шифрування; закритий");
Console.WriteLine("ключ залишається в таємниці й потрібен для розшифрування. Так двоє можуть обмінюватися таємними");
Console.WriteLine("повідомленнями без попереднього обміну спільним секретом — у цьому головна перевага асиметричних шифрів.");

studentA.Dispose(); studentB.Dispose();

// Шифрування повідомлення відкритим ключем одержувача, завантаженим із файлу.
void SendGreeting(string who, string publicKeyFile, string text)
{
    byte[] cipher = EncryptWithPublicFile(publicKeyFile, text);
    Console.WriteLine($"  → {who} ({Path.GetFileName(publicKeyFile)}): зашифровано {cipher.Length} байт, " +
                      $"Base64: {Convert.ToBase64String(cipher)[..48]}…");
}

static byte[] EncryptWithPublicFile(string publicKeyFile, string text)
{
    using var rsa = RSA.Create();
    rsa.FromXmlString(File.ReadAllText(publicKeyFile));   // достатньо лише відкритого ключа
    return rsa.Encrypt(Encoding.UTF8.GetBytes(text), RSAEncryptionPadding.OaepSHA256);
}
