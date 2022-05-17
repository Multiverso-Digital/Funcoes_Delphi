unit Funcoes;

interface

uses Windows, Forms, Messages, SysUtils, Classes, StrUtils, Math, DCPcrypt,
     Cast128, base64, PerlRegEx, Registry, WinInet, IdGlobal, Wcrypt2;


function CaixaMista (mNome: string): string;
Function Poezero(num:integer):string;
function TestaCgc(xCGC: String):Boolean;
function Tiraponto(S:string):String;
function CheckCPF(cpf: string): boolean;
function SiglaUF(S:string):boolean;
function VerificaEmail(s:string):Boolean;
function CheckMod11(num: integer): integer;
function TiraAcentos(Str:string):String;
function MascaraTelefone(S:string):String;
function EncryptSTR(const InString:string; StartKey,MultKey,AddKey:Integer): string;
function DecryptSTR(const InString:string; StartKey,MultKey,AddKey:Integer): string;
function colocaPontoCPF(S:String):String;
function geraSenha(Qtd_Letra1:integer; Qtd_Numero:integer; Qtd_Letra2:Integer):String;
function acertaemail(email:string):TstringList;
function limpaemail(email:string):string;
function Decripta(S1:AnsiString):AnsiString;
function buscaRegexp(oque,aonde:string;forma:Integer):boolean;
function ExtrairRegexp(oque,aonde:string):String;
function MontaItensCabec(Cab:string):string;
function PegaItensCabec(Item, cabec:String):String;
function pegaDominio(Email:string):String;
function VeSeTemWildcard(S:string):Boolean;
function GetRegistryData(RootKey: HKEY; Key, Value: string): variant;
Function PegaValorXml(S:String;Tagini:String;TagFim:String):string;
Function PegaValorSite(S:String;Tagini:String;Tipo:Integer):string;
function IsLike(AString, Pattern: string): boolean;
function IPtoStr(IP: LongWord): String;
function ConvertCharset(AString: String; AMatrix: string): String;
function HexToDec(Str: string): Integer;
function ConveCharHexa(Body:string;Charset:string):string;
function EnCrypt_Decrypt(Action, Src, Key : String) : String;
procedure CryptFile(const SourceFileName, DestinationFileName, Password: string; ToCrypt: Boolean);

const
 FirstCodes : string =
   #1#2#3#4#5#6#7#8#9#10#11#12#13#14#15#16#17#18#19#20#21#22#23#24#25#26#27#28+
  #29#30#31' !"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^' +
   '_`abcdefghijklmnopqrstuvwxyz{|}~';
 cmAnsiToKoi8R: string = 'ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—?™љ›њќћџ ЎўЈ¤Ґ¦§Ё©Є«¬­®Ї°±Ііґµ¶·Ј—є»јЅѕїбвчздецъй'
   + 'клмнопртуфхжигюыэящшьасБВЧЗДЕЦЪЙКЛМНОПРТУФХЖИГЮЫЭЯЩШЬАС';
 cmAnsiToKoi8U: string = 'ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—?™љ›њќћџ ЎўЈ¤Ґ¦§Ё©Є«¬­®Ї°±Ііґµ¶·Ј—є»јЅѕїбвчздецъй'
   + 'клмнопртуфхжигюыэящшьасБВЧЗДЕЦЪЙКЛМНОПРТУФХЖИГЮЫЭЯЩШЬАС';
 cmKoi8RToAnsi: string = '-¦-¬L-++T++---¦¦---?¦•v??? ?°?·?=¦-ёгг¬¬¬LLL---¦¦¦¦Ё¦¦TTT¦¦¦+++©юабцдефгх'
   + 'ийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ';
 cmKoi8UToAnsi: string = '-¦-¬L-++T++---¦¦---?¦•v??? ?°?·?=¦-ёєгії¬LLL-ґў¦¦¦¦ЁЄ¦ІЇT¦¦¦+ҐЎ©юабцдефгх'
   + 'ийклмнопярстужвьызшэщчъЮАБЦДЕФГХИЙКЛМНОПЯРСТУЖВЬЫЗШЭЩЧЪ';
 cmOemDosToAnsi: string = 'АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп---¦+¦¦¬¬¦¦¬---¬L+T+-+¦¦L'
   + 'г¦T¦=+¦¦TTLL-г++----¦¦-рстуфхцчшщъыьэюяЁёЄєЇїЎў°•·v№¤¦ ';
 cmIsoToAnsi: string = '???????????????????????????????? ЁЂЃЄЅІЇЈЉЊЋЌ­ЎЏАБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШ'
   + 'ЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя№ёђѓєѕіїјљњћќ§ўџ';


{Latin-1
  Danish, Dutch, English, Faeroese, Finnish, French, German, Icelandic,
  Irish, Italian, Norwegian, Portuguese, Spanish and Swedish.
}
  CharISO_8859_1: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $00A1, $00A2, $00A3, $00A4, $00A5, $00A6, $00A7,
    $00A8, $00A9, $00AA, $00AB, $00AC, $00AD, $00AE, $00AF,
    $00B0, $00B1, $00B2, $00B3, $00B4, $00B5, $00B6, $00B7,
    $00B8, $00B9, $00BA, $00BB, $00BC, $00BD, $00BE, $00BF,
    $00C0, $00C1, $00C2, $00C3, $00C4, $00C5, $00C6, $00C7,
    $00C8, $00C9, $00CA, $00CB, $00CC, $00CD, $00CE, $00CF,
    $00D0, $00D1, $00D2, $00D3, $00D4, $00D5, $00D6, $00D7,
    $00D8, $00D9, $00DA, $00DB, $00DC, $00DD, $00DE, $00DF,
    $00E0, $00E1, $00E2, $00E3, $00E4, $00E5, $00E6, $00E7,
    $00E8, $00E9, $00EA, $00EB, $00EC, $00ED, $00EE, $00EF,
    $00F0, $00F1, $00F2, $00F3, $00F4, $00F5, $00F6, $00F7,
    $00F8, $00F9, $00FA, $00FB, $00FC, $00FD, $00FE, $00FF
    );

{Latin-2
  Albanian, Czech, English, German, Hungarian, Polish, Rumanian,
  Serbo-Croatian, Slovak, Slovene and Swedish.
}
  CharISO_8859_2: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $0104, $02D8, $0141, $00A4, $013D, $015A, $00A7,
    $00A8, $0160, $015E, $0164, $0179, $00AD, $017D, $017B,
    $00B0, $0105, $02DB, $0142, $00B4, $013E, $015B, $02C7,
    $00B8, $0161, $015F, $0165, $017A, $02DD, $017E, $017C,
    $0154, $00C1, $00C2, $0102, $00C4, $0139, $0106, $00C7,
    $010C, $00C9, $0118, $00CB, $011A, $00CD, $00CE, $010E,
    $0110, $0143, $0147, $00D3, $00D4, $0150, $00D6, $00D7,
    $0158, $016E, $00DA, $0170, $00DC, $00DD, $0162, $00DF,
    $0155, $00E1, $00E2, $0103, $00E4, $013A, $0107, $00E7,
    $010D, $00E9, $0119, $00EB, $011B, $00ED, $00EE, $010F,
    $0111, $0144, $0148, $00F3, $00F4, $0151, $00F6, $00F7,
    $0159, $016F, $00FA, $0171, $00FC, $00FD, $0163, $02D9
    );

{Latin-3
  Afrikaans, Catalan, English, Esperanto, French, Galician,
  German, Italian, Maltese and Turkish.
}
  CharISO_8859_3: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $0126, $02D8, $00A3, $00A4, $FFFD, $0124, $00A7,
    $00A8, $0130, $015E, $011E, $0134, $00AD, $FFFD, $017B,
    $00B0, $0127, $00B2, $00B3, $00B4, $00B5, $0125, $00B7,
    $00B8, $0131, $015F, $011F, $0135, $00BD, $FFFD, $017C,
    $00C0, $00C1, $00C2, $FFFD, $00C4, $010A, $0108, $00C7,
    $00C8, $00C9, $00CA, $00CB, $00CC, $00CD, $00CE, $00CF,
    $FFFD, $00D1, $00D2, $00D3, $00D4, $0120, $00D6, $00D7,
    $011C, $00D9, $00DA, $00DB, $00DC, $016C, $015C, $00DF,
    $00E0, $00E1, $00E2, $FFFD, $00E4, $010B, $0109, $00E7,
    $00E8, $00E9, $00EA, $00EB, $00EC, $00ED, $00EE, $00EF,
    $FFFD, $00F1, $00F2, $00F3, $00F4, $0121, $00F6, $00F7,
    $011D, $00F9, $00FA, $00FB, $00FC, $016D, $015D, $02D9
    );

{Latin-4
  Danish, English, Estonian, Finnish, German, Greenlandic,
  Lappish, Latvian, Lithuanian, Norwegian and Swedish.
}
  CharISO_8859_4: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $0104, $0138, $0156, $00A4, $0128, $013B, $00A7,
    $00A8, $0160, $0112, $0122, $0166, $00AD, $017D, $00AF,
    $00B0, $0105, $02DB, $0157, $00B4, $0129, $013C, $02C7,
    $00B8, $0161, $0113, $0123, $0167, $014A, $017E, $014B,
    $0100, $00C1, $00C2, $00C3, $00C4, $00C5, $00C6, $012E,
    $010C, $00C9, $0118, $00CB, $0116, $00CD, $00CE, $012A,
    $0110, $0145, $014C, $0136, $00D4, $00D5, $00D6, $00D7,
    $00D8, $0172, $00DA, $00DB, $00DC, $0168, $016A, $00DF,
    $0101, $00E1, $00E2, $00E3, $00E4, $00E5, $00E6, $012F,
    $010D, $00E9, $0119, $00EB, $0117, $00ED, $00EE, $012B,
    $0111, $0146, $014D, $0137, $00F4, $00F5, $00F6, $00F7,
    $00F8, $0173, $00FA, $00FB, $00FC, $0169, $016B, $02D9
    );

{CYRILLIC
  Bulgarian, Bielorussian, English, Macedonian, Russian,
  Serbo-Croatian and Ukrainian.
}
  CharISO_8859_5: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $0401, $0402, $0403, $0404, $0405, $0406, $0407,
    $0408, $0409, $040A, $040B, $040C, $00AD, $040E, $040F,
    $0410, $0411, $0412, $0413, $0414, $0415, $0416, $0417,
    $0418, $0419, $041A, $041B, $041C, $041D, $041E, $041F,
    $0420, $0421, $0422, $0423, $0424, $0425, $0426, $0427,
    $0428, $0429, $042A, $042B, $042C, $042D, $042E, $042F,
    $0430, $0431, $0432, $0433, $0434, $0435, $0436, $0437,
    $0438, $0439, $043A, $043B, $043C, $043D, $043E, $043F,
    $0440, $0441, $0442, $0443, $0444, $0445, $0446, $0447,
    $0448, $0449, $044A, $044B, $044C, $044D, $044E, $044F,
    $2116, $0451, $0452, $0453, $0454, $0455, $0456, $0457,
    $0458, $0459, $045A, $045B, $045C, $00A7, $045E, $045F
    );

{ARABIC
}
  CharISO_8859_6: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $FFFD, $FFFD, $FFFD, $00A4, $FFFD, $FFFD, $FFFD,
    $FFFD, $FFFD, $FFFD, $FFFD, $060C, $00AD, $FFFD, $FFFD,
    $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD,
    $FFFD, $FFFD, $FFFD, $061B, $FFFD, $FFFD, $FFFD, $061F,
    $FFFD, $0621, $0622, $0623, $0624, $0625, $0626, $0627,
    $0628, $0629, $062A, $062B, $062C, $062D, $062E, $062F,
    $0630, $0631, $0632, $0633, $0634, $0635, $0636, $0637,
    $0638, $0639, $063A, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD,
    $0640, $0641, $0642, $0643, $0644, $0645, $0646, $0647,
    $0648, $0649, $064A, $064B, $064C, $064D, $064E, $064F,
    $0650, $0651, $0652, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD,
    $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD
    );

{GREEK
}
  CharISO_8859_7: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $2018, $2019, $00A3, $FFFD, $FFFD, $00A6, $00A7,
    $00A8, $00A9, $FFFD, $00AB, $00AC, $00AD, $FFFD, $2015,
    $00B0, $00B1, $00B2, $00B3, $0384, $0385, $0386, $00B7,
    $0388, $0389, $038A, $00BB, $038C, $00BD, $038E, $038F,
    $0390, $0391, $0392, $0393, $0394, $0395, $0396, $0397,
    $0398, $0399, $039A, $039B, $039C, $039D, $039E, $039F,
    $03A0, $03A1, $FFFD, $03A3, $03A4, $03A5, $03A6, $03A7,
    $03A8, $03A9, $03AA, $03AB, $03AC, $03AD, $03AE, $03AF,
    $03B0, $03B1, $03B2, $03B3, $03B4, $03B5, $03B6, $03B7,
    $03B8, $03B9, $03BA, $03BB, $03BC, $03BD, $03BE, $03BF,
    $03C0, $03C1, $03C2, $03C3, $03C4, $03C5, $03C6, $03C7,
    $03C8, $03C9, $03CA, $03CB, $03CC, $03CD, $03CE, $FFFD
    );

{HEBREW
}
  CharISO_8859_8: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $FFFD, $00A2, $00A3, $00A4, $00A5, $00A6, $00A7,
    $00A8, $00A9, $00D7, $00AB, $00AC, $00AD, $00AE, $00AF,
    $00B0, $00B1, $00B2, $00B3, $00B4, $00B5, $00B6, $00B7,
    $00B8, $00B9, $00F7, $00BB, $00BC, $00BD, $00BE, $FFFD,
    $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD,
    $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD,
    $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD,
    $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $2017,
    $05D0, $05D1, $05D2, $05D3, $05D4, $05D5, $05D6, $05D7,
    $05D8, $05D9, $05DA, $05DB, $05DC, $05DD, $05DE, $05DF,
    $05E0, $05E1, $05E2, $05E3, $05E4, $05E5, $05E6, $05E7,
    $05E8, $05E9, $05EA, $FFFD, $FFFD, $200E, $200F, $FFFD
    );

{Latin-5
  English, Finnish, French, German, Irish, Italian, Norwegian,
  Portuguese, Spanish, Swedish and Turkish.
}
  CharISO_8859_9: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $0104, $02D8, $0141, $00A4, $013D, $015A, $00A7,
    $00A8, $0160, $015E, $0164, $0179, $00AD, $017D, $017B,
    $00B0, $0105, $02DB, $0142, $00B4, $013E, $015B, $02C7,
    $00B8, $0161, $015F, $0165, $017A, $02DD, $017E, $017C,
    $0154, $00C1, $00C2, $0102, $00C4, $0139, $0106, $00C7,
    $010C, $00C9, $0118, $00CB, $011A, $00CD, $00CE, $010E,
    $011E, $00D1, $00D2, $00D3, $00D4, $00D5, $00D6, $00D7,
    $00D8, $00D9, $00DA, $00DB, $00DC, $0130, $015E, $00DF,
    $00E0, $00E1, $00E2, $00E3, $00E4, $00E5, $00E6, $00E7,
    $00E8, $00E9, $00EA, $00EB, $00EC, $00ED, $00EE, $00EF,
    $011F, $00F1, $00F2, $00F3, $00F4, $00F5, $00F6, $00F7,
    $00F8, $00F9, $00FA, $00FB, $00FC, $0131, $015F, $00FF
    );

{Latin-6
  Danish, English, Estonian, Faeroese, Finnish, German, Greenlandic,
  Icelandic, Lappish, Latvian, Lithuanian, Norwegian and Swedish.
}
  CharISO_8859_10: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $0104, $0112, $0122, $012A, $0128, $0136, $00A7,
    $013B, $0110, $0160, $0166, $017D, $00AD, $016A, $014A,
    $00B0, $0105, $0113, $0123, $012B, $0129, $0137, $00B7,
    $013C, $0111, $0161, $0167, $017E, $2015, $016B, $014B,
    $0100, $00C1, $00C2, $00C3, $00C4, $00C5, $00C6, $012E,
    $010C, $00C9, $0118, $00CB, $0116, $00CD, $00CE, $00CF,
    $00D0, $0145, $014C, $00D3, $00D4, $00D5, $00D6, $0168,
    $00D8, $0172, $00DA, $00DB, $00DC, $00DD, $00DE, $00DF,
    $0101, $00E1, $00E2, $00E3, $00E4, $00E5, $00E6, $012F,
    $010D, $00E9, $0119, $00EB, $0117, $00ED, $00EE, $00EF,
    $00F0, $0146, $014D, $00F3, $00F4, $00F5, $00F6, $0169,
    $00F8, $0173, $00FA, $00FB, $00FC, $00FD, $00FE, $0138
    );

  CharISO_8859_13: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $201D, $00A2, $00A3, $00A4, $201E, $00A6, $00A7,
    $00D8, $00A9, $0156, $00AB, $00AC, $00AD, $00AE, $00C6,
    $00B0, $00B1, $00B2, $00B3, $201C, $00B5, $00B6, $00B7,
    $00F8, $00B9, $0157, $00BB, $00BC, $00BD, $00BE, $00E6,
    $0104, $012E, $0100, $0106, $00C4, $00C5, $0118, $0112,
    $010C, $00C9, $0179, $0116, $0122, $0136, $012A, $013B,
    $0160, $0143, $0145, $00D3, $014C, $00D5, $00D6, $00D7,
    $0172, $0141, $015A, $016A, $00DC, $017B, $017D, $00DF,
    $0105, $012F, $0101, $0107, $00E4, $00E5, $0119, $0113,
    $010D, $00E9, $017A, $0117, $0123, $0137, $012B, $013C,
    $0161, $0144, $0146, $00F3, $014D, $00F5, $00F6, $00F7,
    $0173, $0142, $015B, $016B, $00FC, $017C, $017E, $2019
    );

  CharISO_8859_14: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $1E02, $1E03, $00A3, $010A, $010B, $1E0A, $00A7,
    $1E80, $00A9, $1E82, $1E0B, $1EF2, $00AD, $00AE, $0178,
    $1E1E, $1E1F, $0120, $0121, $1E40, $1E41, $00B6, $1E56,
    $1E81, $1E57, $1E83, $1E60, $1EF3, $1E84, $1E85, $1E61,
    $00C0, $00C1, $00C2, $00C3, $00C4, $00C5, $00C6, $00C7,
    $00C8, $00C9, $00CA, $00CB, $00CC, $00CD, $00CE, $00CF,
    $0174, $00D1, $00D2, $00D3, $00D4, $00D5, $00D6, $1E6A,
    $00D8, $00D9, $00DA, $00DB, $00DC, $00DD, $0176, $00DF,
    $00E0, $00E1, $00E2, $00E3, $00E4, $00E5, $00E6, $00E7,
    $00E8, $00E9, $00EA, $00EB, $00EC, $00ED, $00EE, $00EF,
    $0175, $00F1, $00F2, $00F3, $00F4, $00F5, $00F6, $1E6B,
    $00F8, $00F9, $00FA, $00FB, $00FC, $00FD, $0177, $00FF
    );

  CharISO_8859_15: array[128..255] of Word =
  (
    $0080, $0081, $0082, $0083, $0084, $0085, $0086, $0087,
    $0088, $0089, $008A, $008B, $008C, $008D, $008E, $008F,
    $0090, $0091, $0092, $0093, $0094, $0095, $0096, $0097,
    $0098, $0099, $009A, $009B, $009C, $009D, $009E, $009F,
    $00A0, $00A1, $00A2, $00A3, $20AC, $00A5, $0160, $00A7,
    $0161, $00A9, $00AA, $00AB, $00AC, $00AD, $00AE, $00AF,
    $00B0, $00B1, $00B2, $00B3, $017D, $00B5, $00B6, $00B7,
    $017E, $00B9, $00BA, $00BB, $0152, $0153, $0178, $00BF,
    $00C0, $00C1, $00C2, $00C3, $00C4, $00C5, $00C6, $00C7,
    $00C8, $00C9, $00CA, $00CB, $00CC, $00CD, $00CE, $00CF,
    $00D0, $00D1, $00D2, $00D3, $00D4, $00D5, $00D6, $00D7,
    $00D8, $00D9, $00DA, $00DB, $00DC, $00DD, $00DE, $00DF,
    $00E0, $00E1, $00E2, $00E3, $00E4, $00E5, $00E6, $00E7,
    $00E8, $00E9, $00EA, $00EB, $00EC, $00ED, $00EE, $00EF,
    $00F0, $00F1, $00F2, $00F3, $00F4, $00F5, $00F6, $00F7,
    $00F8, $00F9, $00FA, $00FB, $00FC, $00FD, $00FE, $00FF
    );

{Eastern European
}
  CharCP_1250: array[128..255] of Word =
  (
    $20AC, $FFFD, $201A, $FFFD, $201E, $2026, $2020, $2021,
    $FFFD, $2030, $0160, $2039, $015A, $0164, $017D, $0179,
    $FFFD, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $FFFD, $2122, $0161, $203A, $015B, $0165, $017E, $017A,
    $00A0, $02C7, $02D8, $0141, $00A4, $0104, $00A6, $00A7,
    $00A8, $00A9, $015E, $00AB, $00AC, $00AD, $00AE, $017B,
    $00B0, $00B1, $02DB, $0142, $00B4, $00B5, $00B6, $00B7,
    $00B8, $0105, $015F, $00BB, $013D, $02DD, $013E, $017C,
    $0154, $00C1, $00C2, $0102, $00C4, $0139, $0106, $00C7,
    $010C, $00C9, $0118, $00CB, $011A, $00CD, $00CE, $010E,
    $0110, $0143, $0147, $00D3, $00D4, $0150, $00D6, $00D7,
    $0158, $016E, $00DA, $0170, $00DC, $00DD, $0162, $00DF,
    $0155, $00E1, $00E2, $0103, $00E4, $013A, $0107, $00E7,
    $010D, $00E9, $0119, $00EB, $011B, $00ED, $00EE, $010F,
    $0111, $0144, $0148, $00F3, $00F4, $0151, $00F6, $00F7,
    $0159, $016F, $00FA, $0171, $00FC, $00FD, $0163, $02D9
    );

{Cyrillic
}
  CharCP_1251: array[128..255] of Word =
  (
    $0402, $0403, $201A, $0453, $201E, $2026, $2020, $2021,
    $20AC, $2030, $0409, $2039, $040A, $040C, $040B, $040F,
    $0452, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $FFFD, $2122, $0459, $203A, $045A, $045C, $045B, $045F,
    $00A0, $040E, $045E, $0408, $00A4, $0490, $00A6, $00A7,
    $0401, $00A9, $0404, $00AB, $00AC, $00AD, $00AE, $0407,
    $00B0, $00B1, $0406, $0456, $0491, $00B5, $00B6, $00B7,
    $0451, $2116, $0454, $00BB, $0458, $0405, $0455, $0457,
    $0410, $0411, $0412, $0413, $0414, $0415, $0416, $0417,
    $0418, $0419, $041A, $041B, $041C, $041D, $041E, $041F,
    $0420, $0421, $0422, $0423, $0424, $0425, $0426, $0427,
    $0428, $0429, $042A, $042B, $042C, $042D, $042E, $042F,
    $0430, $0431, $0432, $0433, $0434, $0435, $0436, $0437,
    $0438, $0439, $043A, $043B, $043C, $043D, $043E, $043F,
    $0440, $0441, $0442, $0443, $0444, $0445, $0446, $0447,
    $0448, $0449, $044A, $044B, $044C, $044D, $044E, $044F
    );

{Latin-1 (US, Western Europe)
}
  CharCP_1252: array[128..255] of Word =
  (
    $20AC, $FFFD, $201A, $0192, $201E, $2026, $2020, $2021,
    $02C6, $2030, $0160, $2039, $0152, $FFFD, $017D, $FFFD,
    $FFFD, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $02DC, $2122, $0161, $203A, $0153, $FFFD, $017E, $0178,
    $00A0, $00A1, $00A2, $00A3, $00A4, $00A5, $00A6, $00A7,
    $00A8, $00A9, $00AA, $00AB, $00AC, $00AD, $00AE, $00AF,
    $00B0, $00B1, $00B2, $00B3, $00B4, $00B5, $00B6, $00B7,
    $00B8, $00B9, $00BA, $00BB, $00BC, $00BD, $00BE, $00BF,
    $00C0, $00C1, $00C2, $00C3, $00C4, $00C5, $00C6, $00C7,
    $00C8, $00C9, $00CA, $00CB, $00CC, $00CD, $00CE, $00CF,
    $00D0, $00D1, $00D2, $00D3, $00D4, $00D5, $00D6, $00D7,
    $00D8, $00D9, $00DA, $00DB, $00DC, $00DD, $00DE, $00DF,
    $00E0, $00E1, $00E2, $00E3, $00E4, $00E5, $00E6, $00E7,
    $00E8, $00E9, $00EA, $00EB, $00EC, $00ED, $00EE, $00EF,
    $00F0, $00F1, $00F2, $00F3, $00F4, $00F5, $00F6, $00F7,
    $00F8, $00F9, $00FA, $00FB, $00FC, $00FD, $00FE, $00FF
    );

{Greek
}
  CharCP_1253: array[128..255] of Word =
  (
    $20AC, $FFFD, $201A, $0192, $201E, $2026, $2020, $2021,
    $FFFD, $2030, $FFFD, $2039, $FFFD, $FFFD, $FFFD, $FFFD,
    $FFFD, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $FFFD, $2122, $FFFD, $203A, $FFFD, $FFFD, $FFFD, $FFFD,
    $00A0, $0385, $0386, $00A3, $00A4, $00A5, $00A6, $00A7,
    $00A8, $00A9, $FFFD, $00AB, $00AC, $00AD, $00AE, $2015,
    $00B0, $00B1, $00B2, $00B3, $0384, $00B5, $00B6, $00B7,
    $0388, $0389, $038A, $00BB, $038C, $00BD, $038E, $038F,
    $0390, $0391, $0392, $0393, $0394, $0395, $0396, $0397,
    $0398, $0399, $039A, $039B, $039C, $039D, $039E, $039F,
    $03A0, $03A1, $FFFD, $03A3, $03A4, $03A5, $03A6, $03A7,
    $03A8, $03A9, $03AA, $03AB, $03AC, $03AD, $03AE, $03AF,
    $03B0, $03B1, $03B2, $03B3, $03B4, $03B5, $03B6, $03B7,
    $03B8, $03B9, $03BA, $03BB, $03BC, $03BD, $03BE, $03BF,
    $03C0, $03C1, $03C2, $03C3, $03C4, $03C5, $03C6, $03C7,
    $03C8, $03C9, $03CA, $03CB, $03CC, $03CD, $03CE, $FFFD
    );

{Turkish
}
  CharCP_1254: array[128..255] of Word =
  (
    $20AC, $FFFD, $201A, $0192, $201E, $2026, $2020, $2021,
    $02C6, $2030, $0160, $2039, $0152, $FFFD, $FFFD, $FFFD,
    $FFFD, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $02DC, $2122, $0161, $203A, $0153, $FFFD, $FFFD, $0178,
    $00A0, $00A1, $00A2, $00A3, $00A4, $00A5, $00A6, $00A7,
    $00A8, $00A9, $00AA, $00AB, $00AC, $00AD, $00AE, $00AF,
    $00B0, $00B1, $00B2, $00B3, $00B4, $00B5, $00B6, $00B7,
    $00B8, $00B9, $00BA, $00BB, $00BC, $00BD, $00BE, $00BF,
    $00C0, $00C1, $00C2, $00C3, $00C4, $00C5, $00C6, $00C7,
    $00C8, $00C9, $00CA, $00CB, $00CC, $00CD, $00CE, $00CF,
    $011E, $00D1, $00D2, $00D3, $00D4, $00D5, $00D6, $00D7,
    $00D8, $00D9, $00DA, $00DB, $00DC, $0130, $015E, $00DF,
    $00E0, $00E1, $00E2, $00E3, $00E4, $00E5, $00E6, $00E7,
    $00E8, $00E9, $00EA, $00EB, $00EC, $00ED, $00EE, $00EF,
    $011F, $00F1, $00F2, $00F3, $00F4, $00F5, $00F6, $00F7,
    $00F8, $00F9, $00FA, $00FB, $00FC, $0131, $015F, $00FF
    );

{Hebrew
}
  CharCP_1255: array[128..255] of Word =
  (
    $20AC, $FFFD, $201A, $0192, $201E, $2026, $2020, $2021,
    $02C6, $2030, $FFFD, $2039, $FFFD, $FFFD, $FFFD, $FFFD,
    $FFFD, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $02DC, $2122, $FFFD, $203A, $FFFD, $FFFD, $FFFD, $FFFD,
    $00A0, $00A1, $00A2, $00A3, $20AA, $00A5, $00A6, $00A7,
    $00A8, $00A9, $00D7, $00AB, $00AC, $00AD, $00AE, $00AF,
    $00B0, $00B1, $00B2, $00B3, $00B4, $00B5, $00B6, $00B7,
    $00B8, $00B9, $00F7, $00BB, $00BC, $00BD, $00BE, $00BF,
    $05B0, $05B1, $05B2, $05B3, $05B4, $05B5, $05B6, $05B7,
    $05B8, $05B9, $FFFD, $05BB, $05BC, $05BD, $05BE, $05BF,
    $05C0, $05C1, $05C2, $05C3, $05F0, $05F1, $05F2, $05F3,
    $05F4, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD, $FFFD,
    $05D0, $05D1, $05D2, $05D3, $05D4, $05D5, $05D6, $05D7,
    $05D8, $05D9, $05DA, $05DB, $05DC, $05DD, $05DE, $05DF,
    $05E0, $05E1, $05E2, $05E3, $05E4, $05E5, $05E6, $05E7,
    $05E8, $05E9, $05EA, $FFFD, $FFFD, $200E, $200F, $FFFD
    );

{Arabic
}
  CharCP_1256: array[128..255] of Word =
  (
    $20AC, $067E, $201A, $0192, $201E, $2026, $2020, $2021,
    $02C6, $2030, $0679, $2039, $0152, $0686, $0698, $0688,
    $06AF, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $06A9, $2122, $0691, $203A, $0153, $200C, $200D, $06BA,
    $00A0, $060C, $00A2, $00A3, $00A4, $00A5, $00A6, $00A7,
    $00A8, $00A9, $06BE, $00AB, $00AC, $00AD, $00AE, $00AF,
    $00B0, $00B1, $00B2, $00B3, $00B4, $00B5, $00B6, $00B7,
    $00B8, $00B9, $061B, $00BB, $00BC, $00BD, $00BE, $061F,
    $06C1, $0621, $0622, $0623, $0624, $0625, $0626, $0627,
    $0628, $0629, $062A, $062B, $062C, $062D, $062E, $062F,
    $0630, $0631, $0632, $0633, $0634, $0635, $0636, $00D7,
    $0637, $0638, $0639, $063A, $0640, $0641, $0642, $0643,
    $00E0, $0644, $00E2, $0645, $0646, $0647, $0648, $00E7,
    $00E8, $00E9, $00EA, $00EB, $0649, $064A, $00EE, $00EF,
    $064B, $064C, $064D, $064E, $00F4, $064F, $0650, $00F7,
    $0651, $00F9, $0652, $00FB, $00FC, $200E, $200F, $06D2
    );

{Baltic
}
  CharCP_1257: array[128..255] of Word =
  (
    $20AC, $FFFD, $201A, $FFFD, $201E, $2026, $2020, $2021,
    $FFFD, $2030, $FFFD, $2039, $FFFD, $00A8, $02C7, $00B8,
    $FFFD, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $FFFD, $2122, $FFFD, $203A, $FFFD, $00AF, $02DB, $FFFD,
    $00A0, $FFFD, $00A2, $00A3, $00A4, $FFFD, $00A6, $00A7,
    $00D8, $00A9, $0156, $00AB, $00AC, $00AD, $00AE, $00C6,
    $00B0, $00B1, $00B2, $00B3, $00B4, $00B5, $00B6, $00B7,
    $00F8, $00B9, $0157, $00BB, $00BC, $00BD, $00BE, $00E6,
    $0104, $012E, $0100, $0106, $00C4, $00C5, $0118, $0112,
    $010C, $00C9, $0179, $0116, $0122, $0136, $012A, $013B,
    $0160, $0143, $0145, $00D3, $014C, $00D5, $00D6, $00D7,
    $0172, $0141, $015A, $016A, $00DC, $017B, $017D, $00DF,
    $0105, $012F, $0101, $0107, $00E4, $00E5, $0119, $0113,
    $010D, $00E9, $017A, $0117, $0123, $0137, $012B, $013C,
    $0161, $0144, $0146, $00F3, $014D, $00F5, $00F6, $00F7,
    $0173, $0142, $015B, $016B, $00FC, $017C, $017E, $02D9
    );

{Vietnamese
}
  CharCP_1258: array[128..255] of Word =
  (
    $20AC, $FFFD, $201A, $0192, $201E, $2026, $2020, $2021,
    $02C6, $2030, $FFFD, $2039, $0152, $FFFD, $FFFD, $FFFD,
    $FFFD, $2018, $2019, $201C, $201D, $2022, $2013, $2014,
    $02DC, $2122, $FFFD, $203A, $0153, $FFFD, $FFFD, $0178,
    $00A0, $00A1, $00A2, $00A3, $00A4, $00A5, $00A6, $00A7,
    $00A8, $00A9, $00AA, $00AB, $00AC, $00AD, $00AE, $00AF,
    $00B0, $00B1, $00B2, $00B3, $00B4, $00B5, $00B6, $00B7,
    $00B8, $00B9, $00BA, $00BB, $00BC, $00BD, $00BE, $00BF,
    $00C0, $00C1, $00C2, $0102, $00C4, $00C5, $00C6, $00C7,
    $00C8, $00C9, $00CA, $00CB, $0300, $00CD, $00CE, $00CF,
    $0110, $00D1, $0309, $00D3, $00D4, $01A0, $00D6, $00D7,
    $00D8, $00D9, $00DA, $00DB, $00DC, $01AF, $0303, $00DF,
    $00E0, $00E1, $00E2, $0103, $00E4, $00E5, $00E6, $00E7,
    $00E8, $00E9, $00EA, $00EB, $0301, $00ED, $00EE, $00EF,
    $0111, $00F1, $0323, $00F3, $00F4, $01A1, $00F6, $00F7,
    $00F8, $00F9, $00FA, $00FB, $00FC, $01B0, $20AB, $00FF
    );

{Cyrillic
}
  CharKOI8_R: array[128..255] of Word =
  (
    $2500, $2502, $250C, $2510, $2514, $2518, $251C, $2524,
    $252C, $2534, $253C, $2580, $2584, $2588, $258C, $2590,
    $2591, $2592, $2593, $2320, $25A0, $2219, $221A, $2248,
    $2264, $2265, $00A0, $2321, $00B0, $00B2, $00B7, $00F7,
    $2550, $2551, $2552, $0451, $2553, $2554, $2555, $2556,
    $2557, $2558, $2559, $255A, $255B, $255C, $255D, $255E,
    $255F, $2560, $2561, $0401, $2562, $2563, $2564, $2565,
    $2566, $2567, $2568, $2569, $256A, $256B, $256C, $00A9,
    $044E, $0430, $0431, $0446, $0434, $0435, $0444, $0433,
    $0445, $0438, $0439, $043A, $043B, $043C, $043D, $043E,
    $043F, $044F, $0440, $0441, $0442, $0443, $0436, $0432,
    $044C, $044B, $0437, $0448, $044D, $0449, $0447, $044A,
    $042E, $0410, $0411, $0426, $0414, $0415, $0424, $0413,
    $0425, $0418, $0419, $041A, $041B, $041C, $041D, $041E,
    $041F, $042F, $0420, $0421, $0422, $0423, $0416, $0412,
    $042C, $042B, $0417, $0428, $042D, $0429, $0427, $042A
    );

{Czech (Kamenicky)
}
  CharCP_895: array[128..255] of Word =
  (
    $010C, $00FC, $00E9, $010F, $00E4, $010E, $0164, $010D,
    $011B, $011A, $0139, $00CD, $013E, $013A, $00C4, $00C1,
    $00C9, $017E, $017D, $00F4, $00F6, $00D3, $016F, $00DA,
    $00FD, $00D6, $00DC, $0160, $013D, $00DD, $0158, $0165,
    $00E1, $00ED, $00F3, $00FA, $0148, $0147, $016E, $00D4,
    $0161, $0159, $0155, $0154, $00BC, $00A7, $00AB, $00BB,
    $2591, $2592, $2593, $2502, $2524, $2561, $2562, $2556,
    $2555, $2563, $2551, $2557, $255D, $255C, $255B, $2510,
    $2514, $2534, $252C, $251C, $2500, $253C, $255E, $255F,
    $255A, $2554, $2569, $2566, $2560, $2550, $256C, $2567,
    $2568, $2564, $2565, $2559, $2558, $2552, $2553, $256B,
    $256A, $2518, $250C, $2588, $2584, $258C, $2590, $2580,
    $03B1, $03B2, $0393, $03C0, $03A3, $03C3, $03BC, $03C4,
    $03A6, $0398, $03A9, $03B4, $221E, $2205, $03B5, $2229,
    $2261, $00B1, $2265, $2264, $2320, $2321, $00F7, $2248,
    $2218, $00B7, $2219, $221A, $207F, $00B2, $25A0, $00A0
    );

{Eastern European
}
  CharCP_852: array[128..255] of Word =
  (
    $00C7, $00FC, $00E9, $00E2, $00E4, $016F, $0107, $00E7,
    $0142, $00EB, $0150, $0151, $00EE, $0179, $00C4, $0106,
    $00C9, $0139, $013A, $00F4, $00F6, $013D, $013E, $015A,
    $015B, $00D6, $00DC, $0164, $0165, $0141, $00D7, $010D,
    $00E1, $00ED, $00F3, $00FA, $0104, $0105, $017D, $017E,
    $0118, $0119, $00AC, $017A, $010C, $015F, $00AB, $00BB,
    $2591, $2592, $2593, $2502, $2524, $00C1, $00C2, $011A,
    $015E, $2563, $2551, $2557, $255D, $017B, $017C, $2510,
    $2514, $2534, $252C, $251C, $2500, $253C, $0102, $0103,
    $255A, $2554, $2569, $2566, $2560, $2550, $256C, $00A4,
    $0111, $0110, $010E, $00CB, $010F, $0147, $00CD, $00CE,
    $011B, $2518, $250C, $2588, $2584, $0162, $016E, $2580,
    $00D3, $00DF, $00D4, $0143, $0144, $0148, $0160, $0161,
    $0154, $00DA, $0155, $0170, $00FD, $00DD, $0163, $00B4,
    $00AD, $02DD, $02DB, $02C7, $02D8, $00A7, $00F7, $00B8,
    $00B0, $00A8, $02D9, $0171, $0158, $0159, $25A0, $00A0
    );

{==============================================================================}



var
 crip : TDCP_cast128;

implementation


//usage action= E(encrypt) ou D(decript)
function EnCrypt_Decrypt(Action, Src, Key : String) : String;
var
   KeyLen    : Integer;
   KeyPos    : Integer;
   offset    : Integer;
   dest      : string;
   SrcPos    : Integer;
   SrcAsc    : Integer;
   TmpSrcAsc : Integer;
   Range     : Integer;
begin
     dest:='';
     KeyLen:=Length(Key);
     KeyPos:=0;
     SrcPos:=0;
     SrcAsc:=0;
     Range:=256;
     if Action = UpperCase('E') then
     begin
          Randomize;
          offset:=Random(Range);
          dest:=format('%1.2x',[offset]);
          for SrcPos := 1 to Length(Src) do
          begin
               SrcAsc:=(Ord(Src[SrcPos]) + offset) MOD 255;
               if KeyPos < KeyLen then KeyPos:= KeyPos + 1 else KeyPos:=1;
               SrcAsc:= SrcAsc xor Ord(Key[KeyPos]);
               dest:=dest + format('%1.2x',[SrcAsc]);
               offset:=SrcAsc;
          end;
     end;
     if Action = UpperCase('D') then
     begin
          offset:=StrToInt('$'+ copy(src,1,2));
          SrcPos:=3;
          repeat
                SrcAsc:=StrToInt('$'+ copy(src,SrcPos,2));
                if KeyPos < KeyLen Then KeyPos := KeyPos + 1 else KeyPos := 1;
                TmpSrcAsc := SrcAsc xor Ord(Key[KeyPos]);
                if TmpSrcAsc <= offset then
                     TmpSrcAsc := 255 + TmpSrcAsc - offset
                else
                     TmpSrcAsc := TmpSrcAsc - offset;
                dest := dest + chr(TmpSrcAsc);
                offset:=srcAsc;
                SrcPos:=SrcPos + 2;
          until SrcPos >= Length(Src);
     end;
     Result:=dest;
end;




//usage: para criptografar  CryptFile('C:\@Estudo\pais.cds', 'C:\@Estudo\encrypted_pais.dat', 'laranja', True);
//usage: para decriptar    CryptFile('C:\@Estudo\encrypted_pais.dat', 'C:\@Estudo\teste.cds', 'laranja', False);

procedure CryptFile(const SourceFileName, DestinationFileName, Password: string; ToCrypt: Boolean);
var
  hProv: HCRYPTPROV;
  hash: HCRYPTHASH;
  key: HCRYPTKEY;

  Buffer: PByte;
  len: dWord;
  fsIn, fsOut: TFileStream;
  IsEndOfFile: Boolean;
begin
  {get context for crypt default provider}
  CryptAcquireContext(@hProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  {create hash-object (SHA algorithm)}
  CryptCreateHash(hProv, CALG_SHA, 0, 0, @hash);
  {get hash from password}
  CryptHashData(hash, @Password[1], Length(Password), 0);
  {create key from hash by RC4 algorithm}
  CryptDeriveKey(hProv, CALG_RC4, hash, 0, @key);
  {destroy hash-object}
  CryptDestroyHash(hash);

  {open source+destination files}
  fsIn := TFileStream.Create(SourceFileName, fmOpenRead or fmShareDenyWrite);
  fsOut := TFileStream.Create(DestinationFileName, fmCreate);
  try
    {allocate buffer to read content from source file}
    GetMem(Buffer, 512);

    repeat
      IsEndOfFile := (fsIn.Position >= fsIn.Size);
      if IsEndOfFile then break;

      {read content from source file}
      len := fsIn.Read(Buffer^, 512);

      if ToCrypt then
        {crypt buffer}
        CryptEncrypt(key, 0, IsEndOfFile, 0, Buffer, @len, len)
      else
        {decrypt buffer}
        CryptDecrypt(key, 0, IsEndOfFile, 0, Buffer, @len);

      {write changed buffer to destination file}
      fsOut.Write(Buffer^, len)
    until IsEndOfFile;

    {release memory allocated for buffer}
    FreeMem(Buffer, 512);
  finally
    fsIn.Free;
    fsOut.Free;
  end;

  {release the context for crypt default provider}
  CryptReleaseContext(hProv, 0);
end;





function ConveCharHexa(Body:string;Charset:string):string;
var
 linha:TPerlRegEx;
 achou,cara,resu: string;
 intHexa:Integer;

 begin

resu := body;
linha := TPerlRegEx.Create(nil);

linha.Options := [precaseless];
linha.RegEx := '\=[\dA-F][\dA-F]';
linha.Subject := resu;

while linha.MatchAgain do
begin

achou := linha.MatchedExpression;
intHexa := HexToDec(achou);
cara :=  Charset[intHexa];
resu:=stringreplace(resu,achou,cara,[rfReplaceAll]);


end;
linha.Free;
result:=resu;








end;

function HexToDec(Str: string): Integer;
var
  i, M: Integer;
begin
  Result:=0;
  M:=1;
  Str:=AnsiUpperCase(Str);
  for i:=Length(Str) downto 1 do
  begin
    case Str[i] of
      '1'..'9': Result:=Result+(Ord(Str[i])-Ord('0'))*M;
      'A'..'F': Result:=Result+(Ord(Str[i])-Ord('A')+10)*M;
    end;
    M:=M shl 4;
  end;
end;












function ConvertCharset(AString: String; AMatrix: string): String;
var
 i    : Integer;
 cara : integer;
begin
 Result := '';
 for i:= 1 to Length(AString) do
   begin
   cara := ord(FirstCodes[Ord(AString[i])]);
   Result := Result + AMatrix[cara];
   end;
end;



function IPtoStr(IP: LongWord): String;
begin
  Result := Format('%d.%d.%d.%d',     [
           (IP and $ff000000) shr 24,
    (IP and $00ff0000) shr 16,
         (IP and $0000ff00) shr 8,
       (IP and $000000ff) shr 0   ]);
end;


function IsLike(AString, Pattern: string): boolean;
var
   j, n, n1, n2: integer ;
   p1, p2: pchar ;
label
   match, nomatch;
begin
   AString := UpperCase(AString) ;
   Pattern := UpperCase(Pattern) ;
   n1 := Length(AString) ;
   n2 := Length(Pattern) ;
   if n1 < n2 then n := n1 else n := n2;
   p1 := pchar(AString) ;
   p2 := pchar(Pattern) ;
   for j := 1 to n do begin
     if p2^ = '*' then goto match;
     if (p2^ <> '?') and ( p2^ <> p1^ ) then goto nomatch;
     inc(p1) ; inc(p2) ;
   end;
   if n1 > n2 then begin
nomatch:
     Result := False;
     exit;
   end else if n1 < n2 then begin
     for j := n1 + 1 to n2 do begin
       if not ( p2^ in ['*','?'] ) then goto nomatch ;
       inc(p2) ;
     end;
   end;
match:
   Result := True




end;





Function PegaValorSite(S:String;Tagini:String;Tipo:Integer):string;
var
achouini, achoufim, I, comeca : integer;
monta : string;
begin


Result := '';
monta := '';

achouini := pos(tagini,S);

if achouini < 1  then exit;


if tipo = 1 then
   begin
     result := copy(S,achouini+16,2);
     exit;
   end;



for I:= achouini to  length(s) do
begin
  if s[i] = '>' then
  begin
  comeca := I;
  Break;
  end;
end;

I := comeca+1;
while s[i] <> '<' do
begin
  monta := monta + s[i];
  i:=I+1;
end;

Result := monta;

end;









Function PegaValorXml(S:String;Tagini:String;TagFim:String):string;
var
achouini, achoufim, I, comeca : integer;
monta : string;
begin


Result := '';
monta := '';

achouini := pos(tagini,S);
achouFim := pos(tagFim,S);

if achouini < 1  then exit;

for I:= achouini to  length(s) do
begin
  if s[i] = '>' then
  begin
  comeca := I;
  Break;
  end;
end;

I := comeca+1;
while s[i] <> '<' do
begin
  monta := monta + s[i];
  i:=I+1;
end;

Result := monta;

end;



function GetRegistryData(RootKey: HKEY; Key, Value: string): variant;
var
  Reg: TRegistry;
  RegDataType: TRegDataType;
  DataSize, Len: integer;
  s: string;
label cantread;
begin
  Reg := nil;
  try
    Reg := TRegistry.Create(KEY_QUERY_VALUE);
    Reg.RootKey := RootKey;
    if Reg.OpenKeyReadOnly(Key) then begin
      try
        RegDataType := Reg.GetDataType(Value);
        if (RegDataType = rdString) or
           (RegDataType = rdExpandString) then
          Result := Reg.ReadString(Value)
        else if RegDataType = rdInteger then
          Result := Reg.ReadInteger(Value)
        else if RegDataType = rdBinary then begin
          DataSize := Reg.GetDataSize(Value);
          if DataSize = -1 then goto cantread;
          SetLength(s, DataSize);
          Len := Reg.ReadBinaryData(Value, PChar(s)^, DataSize);
          if Len <> DataSize then goto cantread;
          Result := s;
        end else
cantread:
          raise Exception.Create(SysErrorMessage(ERROR_CANTREAD));
      except
        s := ''; // Deallocates memory if allocated
        Reg.CloseKey;
        raise;
      end;
      Reg.CloseKey;
    end else
      raise Exception.Create(SysErrorMessage(GetLastError));
  except
    Reg.Free;
    raise;
  end;
  Reg.Free;
end;



{$R-} {$Q-}
function EncryptSTR(const InString:string; StartKey,MultKey,AddKey:Integer): string;
var I : Byte;
begin
  Result := '';
  for I := 1 to Length(InString) do
  begin
    Result := Result + CHAR(Byte(InString[I]) xor (StartKey shr 8));
    StartKey := (Byte(Result[I]) + StartKey) * MultKey + AddKey;
  end;
end;

function DecryptSTR(const InString:string; StartKey,MultKey,AddKey:Integer): string;
var I : Byte;
begin
  Result := '';
  for I := 1 to Length(InString) do
  begin
    Result := Result + CHAR(Byte(InString[I]) xor (StartKey shr 8));
    StartKey := (Byte(InString[I]) + StartKey) * MultKey + AddKey;
  end;
end;
{$R+} {$Q+}


function VeSeTemWildcard(S:string):Boolean;
begin
Result := false;
  if pos('*',S) > 0 then Result := true;
  if pos('?',S) > 0 then Result := true;
  if pos('+',S) > 0 then Result := true;
end;



function pegaDominio(Email:string):String;
var
achou : integer;
begin

achou := pos('@',email);
if achou > 0 then
begin
result := copy(email,achou,length(email)-(achou-1));
end
else
begin
result := '';
end;


end;




function PegaItensCabec(Item, cabec:String):String;
var
I, J, achou : integer;
Lista    : TstringList;
Monta, ItemNovo    : string;
tem      : Boolean;
begin

Lista      := TstringList.Create;
Lista.Text := Cabec;
Monta := '';

if item = 'Received:' then itemNovo := 'Received: from ' else itemNovo := item;

Tem := false;


for I:= 0 to Lista.Count - 1 do
  begin

    achou := pos(ItemNovo,Lista.Strings[i]);

    if achou = 1 then
       begin
         Monta := Monta + Lista.Strings[i];
         if itemNovo = 'Received: from ' then break;
         J := I+1;
         if J <= Lista.Count-1 then
         begin
         Tem := true;

         while tem do

            begin

            if length(trim(Lista.Strings[J])) > 0 then
            begin
            if not (Lista.Strings[J][1] in ['A'..'Z']) then
                   begin
                   Monta := Monta + Lista.Strings[J];
                   tem := true;
                   end
                   else
                   begin
                    tem := false;
                   end;
            end;

            J := J+1;
            if J > Lista.count-1  then break;
           end;




         end;
       end;

  end;



Result := monta;
Lista.Free;



end;



function MontaItensCabec(Cab:string):string;
var
I , achou     : Integer;
Lista, Cabec  : TstringList;
Testa         : Char;
Monta         : string;
begin

Cabec := TstringList.Create;
Cabec.Text := Cab;
Lista := TstringList.Create;
Lista.Sorted := true;

for I:= 0 to Cabec.Count - 1 do
begin

monta := cabec.Strings[i];
if Length(monta) > 0 then
begin

testa := cabec.Strings[i][1];
if Testa in ['A'..'Z'] then
begin
achou := pos(':',cabec.Strings[i]);

  if achou > 0  then
     begin
       if Lista.IndexOf(copy(cabec.Strings[i],1,achou)) = -1 then
       Lista.Add(copy(cabec.Strings[i],1,achou));
     end;
end;
end;
end;

Result := Lista.Text;

Lista.Free;
Cabec.Free;


end;



function limpaemail(email:string):string;
var
I : integer;
monta : string;
begin

monta := '';

For I:=1 to length(email) do
begin

if email[i] <> ' ' then
   begin
   monta := monta + email[i];
   end;

result := monta;

end;

end;



function acertaemail(email:string):TstringList;
var
monta, montax : string;
I: integer;
tudo, tudoerrado   : string;

work : TstringList;

const
permitido: string=('@-_.');

begin


work := TstringList.create;

monta  := tiraacentos(trim(email))+' ';
montax := '';
tudo   := '';
tudoerrado := '';


For I:=1 to length(monta) do
begin

if (monta[i] in ['A'..'Z']) or
   (monta[i] in ['a'..'z']) or
   (monta[i] in ['0'..'9']) or
   (pos(monta[i],permitido) > 0) then
   begin
   montax := montax + monta[i];
   end
   else
   begin
   if (verificaemail(montax)) then
         begin
         tudo := tudo+montax+';';
         end
         else
         begin
          if (montax<>'') then
          begin
           tudoerrado := tudoerrado+montax+';';
          end;
         end;
   montax := '';
   end;

end;



work.add(tudo);
work.add(tudoerrado);

result := work;


end;






function geraSenha(Qtd_Letra1:integer; Qtd_Numero:integer; Qtd_Letra2:Integer):String;
CONST
Alfa : array[1..21] of string =('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q' ,'R' ,'S' ,'T', 'U', 'V' ,'X' ,'Z');

var senha:String;
I:Integer;
begin
  Randomize;
  Senha := '';
  if Qtd_Letra1>0 then
  begin
    for I:=0 to Qtd_Letra1-1 do
    begin
      senha:=senha+RandomFrom(Alfa);
    end;
  end;
  if Qtd_Numero>0 then
  begin
    for I:=0 to Qtd_Numero-1 do
    begin
        senha:=senha+inttostr(RandomRange(0,9));
    end;
  end;

  if Qtd_Letra2 >0 then
  begin
    for I:=0 to Qtd_Letra2-1 do
    begin
      senha:=senha+RandomFrom(Alfa);
    end;
  end;
  result:=senha;
end;



function colocaPontoCPF(S:String):String;
var monta:string;
begin
  s:=tiraponto(trim(s));
  if length(s)<11 then
  begin
    result:='erro';
  end
  else
  begin
    monta:=copy(s,1,3)+'.'+copy(s,4,3)+'.'+copy(s,7,3)+'-'+copy(s,10,2);
    result:=monta;
  end;
end;


function MascaraTelefone(S:string):String;
var
Monta, tel : string;
begin

tel := tiraponto(trim(S));


If length(tel) < 7 then
   begin
   result := 'ERRO';
   exit;
   end;


If length(tel) = 7 then
   begin
   monta := copy(tel,1,3)+'-'+copy(tel,4,4);
   end;

If length(tel) = 8 then
   begin
   monta := copy(tel,1,4)+'-'+copy(tel,5,4);
   end;

If length(tel) > 8 then
   begin
   monta := copy(tel,1,4)+'-'+copy(tel,5,4)+' '+copy(tel,9,length(tel)-8);
   end;


Result := monta;

end;


function TiraAcentos(Str:String): String;
Const
    ComAcento = 'àâêôûãõáéíóúçüÀÂÊÔÛÃÕÁÉÍÓÚÇÜ';
    SemAcento = 'aaeouaoaeioucuAAEOUAOAEIOUCU';
Var
    x : Integer;
Begin
    For x := 1 to Length(Str) do
       if Pos(Str[x],ComAcento) <> 0  Then
          Str[x] := SemAcento[Pos(Str[x],ComAcento)];
    Result := Str;
end;



function VerificaEmail(s:string):Boolean;
var
i: integer;
achou : boolean;
begin

if pos('@', s) < 1 then
begin
result:= false;
exit;
end;

achou := false;
for I:= (pos('@',s)+1) to length(s) do
begin
If s[i] = '.' then achou := true;
end;

if pos('..', s) > 0 then achou := false;


result := achou;


end;



function SiglaUF(S:string):boolean;
Var
I : integer;
const
UF : array[1..27] of string = ('AC', 'AL', 'MA', 'RS', 'SC', 'PR', 'SP', 'RJ', 'ES', 'SE', 'BA', 'PB', 'PE', 'RN', 'CE', 'PA', 'PI', 'AM', 'RR', 'RO', 'AP', 'GO', 'TO', 'MG', 'MT', 'MS', 'DF');
begin

result := false;
For I:= 1 to 27 do
begin
If UF[i] = S then result := true;
end;


end;


function CheckMod11(num: integer): integer;
var
  soma, dg1, dg2: integer;
  Cpf,monta: string;
begin


  monta := inttostr(num);
  If length(monta) = 1 then cpf:= '00000'+monta;
  If length(monta) = 2 then cpf:= '0000'+monta;
  If length(monta) = 3 then cpf:= '000'+monta;
  If length(monta) = 4 then cpf:= '00'+monta;
  If length(monta) = 5 then cpf:= '0'+monta;
  If length(monta) = 6 then cpf:= monta;
  soma:=0;
  inc(soma,(ord(cpf[1])-$30)*7);
  inc(soma,(ord(cpf[2])-$30)*6);
  inc(soma,(ord(cpf[3])-$30)*5);
  inc(soma,(ord(cpf[4])-$30)*4);
  inc(soma,(ord(cpf[5])-$30)*3);
  inc(soma,(ord(cpf[6])-$30)*2);
  {
  inc(soma,(ord(cpf[7])-$30)*4);
  inc(soma,(ord(cpf[8])-$30)*3);
  inc(soma,(ord(cpf[9])-$30)*2); }
  dg1:=11-(soma mod 11);
  if dg1>=10 then dg1:=0;

  Result := dg1;

  {
  soma:=0;
  inc(soma,(ord(cpf[1])-$30)*11);
  inc(soma,(ord(cpf[2])-$30)*10);
  inc(soma,(ord(cpf[3])-$30)*9);
  inc(soma,(ord(cpf[4])-$30)*8);
  inc(soma,(ord(cpf[5])-$30)*7);
  inc(soma,(ord(cpf[6])-$30)*6);
  inc(soma,(ord(cpf[7])-$30)*5);
  inc(soma,(ord(cpf[8])-$30)*4);
  inc(soma,(ord(cpf[9])-$30)*3);
  inc(soma,(2*dg1));
  dg2:=11-(soma mod 11);
  if dg2>=10 then dg2:=0;
  CheckCPF:=(cpf[10]=chr(dg1+$30)) and (cpf[11]=chr(dg2+$30));
  }
end;



function CheckCPF(cpf: string): boolean;
var
  soma, dg1, dg2: integer;
begin
  if length(cpf)<>11 then
  begin
    CheckCPF:=false;
    exit;
  end;
  soma:=0;
  inc(soma,(ord(cpf[1])-$30)*10);
  inc(soma,(ord(cpf[2])-$30)*9);
  inc(soma,(ord(cpf[3])-$30)*8);
  inc(soma,(ord(cpf[4])-$30)*7);
  inc(soma,(ord(cpf[5])-$30)*6);
  inc(soma,(ord(cpf[6])-$30)*5);
  inc(soma,(ord(cpf[7])-$30)*4);
  inc(soma,(ord(cpf[8])-$30)*3);
  inc(soma,(ord(cpf[9])-$30)*2);
  dg1:=11-(soma mod 11);
  if dg1>=10 then dg1:=0;
  soma:=0;
  inc(soma,(ord(cpf[1])-$30)*11);
  inc(soma,(ord(cpf[2])-$30)*10);
  inc(soma,(ord(cpf[3])-$30)*9);
  inc(soma,(ord(cpf[4])-$30)*8);
  inc(soma,(ord(cpf[5])-$30)*7);
  inc(soma,(ord(cpf[6])-$30)*6);
  inc(soma,(ord(cpf[7])-$30)*5);
  inc(soma,(ord(cpf[8])-$30)*4);
  inc(soma,(ord(cpf[9])-$30)*3);
  inc(soma,(2*dg1));
  dg2:=11-(soma mod 11);
  if dg2>=10 then dg2:=0;
  CheckCPF:=(cpf[10]=chr(dg1+$30)) and (cpf[11]=chr(dg2+$30));
end;



function Tiraponto(S:string):String;
var
Monta, MOntaX : string;
begin
monta  := stringreplace(S,'.','',[rfReplaceAll, rfIgnoreCase]);
montaX := stringreplace(Monta,'/','',[rfReplaceAll, rfIgnoreCase]);
monta  := stringreplace(MontaX,'-','',[rfReplaceAll, rfIgnoreCase]);
Result := monta;
end;


function CaixaMista (mNome: string): string;
var
tam,pos1,pos2 : integer ;
pal, monta : string;
begin
result := '';
Tam   := Length(mNome);
monta := ansilowercase(mNome);
mNome := TrimRight(monta) + ' ';
while True do
begin
pos1:=POS( ' ' , mNome) ;
if pos1 = 0 then break;
pal := Copy(mNome,1,pos1) ;
pos2 := pos(pal, ' na no ao com á à às de das dos do da e os as a e i o u para em nos nas apto bloco cj quadra ');
If pos2 > 0 then pal :=AnsiLowerCase (pal)
else pal:= AnsiUpperCase(Copy(pal,1,1)) + AnsiLowerCase(Copy(pal,2,tam)) ;
result := Trimleft(result + pal) ;
mNome := copy(mNome,pos1+1,tam)
end;

monta := ansiuppercase(copy(result,1,1));
result := monta + (copy(result,2,length(result)-1));

end;



function TestaCgc(xCGC: String):Boolean;
Var
d1,d4,xx,nCount,fator,resto,digito1,digito2 : Integer;
Check : String;
begin
d1 := 0;
d4 := 0;
xx := 1;


If xCGC = '00000000000000' then
   begin
   result := false;
   exit;
   end;

for nCount := 1 to Length( xCGC )-2 do
    begin
    if Pos( Copy( xCGC, nCount, 1 ), '/-.' ) = 0 then
       begin
       if xx < 5 then
          begin
          fator := 6 - xx;
          end
       else
          begin
          fator := 14 - xx;
          end;
       d1 := d1 + StrToInt( Copy( xCGC, nCount, 1 ) ) * fator;
       if xx < 6 then
          begin
          fator := 7 - xx;
          end
       else
          begin
          fator := 15 - xx;
          end;
       d4 := d4 + StrToInt( Copy( xCGC, nCount, 1 ) ) * fator;
       xx := xx+1;
       end;
    end;
    resto := (d1 mod 11);
    if resto < 2 then
       begin
       digito1 := 0;
       end
   else
       begin
       digito1 := 11 - resto;
       end;
   d4 := d4 + 2 * digito1;
   resto := (d4 mod 11);
   if resto < 2 then
      begin
      digito2 := 0;
      end
   else
      begin
      digito2 := 11 - resto;
      end;
   Check := IntToStr(Digito1) + IntToStr(Digito2);
   if Check <> copy(xCGC,succ(length(xCGC)-2),2) then
      begin
      Result := False;
      end
   else
      begin
      Result := True;
      end;
end;


Function Poezero(num:integer):string;
var
monta : string;
begin

monta := inttostr(num);
Case length(monta) of
1: result := '000'+monta;
2: result := '00'+monta;
3: result := '0'+monta;
4: result := monta;
end;

end;




function Decripta(S1:AnsiString):AnsiString;
var
  i,j: integer;
  Cipher: TDCP_blockcipher;
  S    : AnsiString;

begin
  crip  := TDCP_cast128.Create(nil);
  crip.Algorithm  := 'Cast128';
  crip.BlockSize  := 64;
  crip.MaxKeySize := 128;
  Cipher:= TDCP_blockcipher(crip);
  Cipher.InitStr('1');    // initialize the cipher with the key
 try
  s:= B64Decode(S1);
 except
  Result := '';
  exit;
 end;
           // decode the Base64 encoded string
 // s:= S1;
  Cipher.DecryptCFB(S[1],S[1],Length(S));  // decrypt all of the strings
  Result:= s;
  Cipher.Reset;         // we are using CFB chaining mode so we must reset after each block of encrypted/decrypts
  Cipher.Burn;
end;



function ExtrairRegexp(oque,aonde:string):String;
var
  linha:TPerlRegEx;
begin
  Result := '';
  linha := TPerlRegEx.Create(nil);
  linha.Options := [preCaseLess];
  linha.RegEx := oque;
  linha.Subject := aonde;
  try
  linha.Match;
  result := linha.MatchedExpression;
  except
  Result := '';
  end;

  linha.Destroy;
end;



function buscaRegexp(oque,aonde:string;forma:Integer):boolean;
{  exato: integer = 1;
  contem: integer = 2;
  regex: integer = 3;}
var
  linha:TPerlRegEx;
  monta : string;
begin
  linha := TPerlRegEx.Create(nil);
  case forma of
    1:oque:='\b'+oque+'\b';
    2: begin
       oque:='.{0,}'+oque+'.{0,}';
       monta := stringreplace(oque ,'*','.*',[rfReplaceAll]);
       oque  := stringreplace(monta,'?','.?',[rfReplaceAll]);
       monta := stringreplace(oque ,'+','.+',[rfReplaceAll]);
       oque  := monta;
       end;
    3:oque:=oque;
  end;
  linha.Options := [preCaseLess];
  linha.RegEx   := oque;
  linha.Subject := aonde;
  try
  result:=linha.Match;
  except
  Result := False;
  end;
  linha.DestroyComponents;
end;





end.
