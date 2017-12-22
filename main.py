from AesCipher import CBC
from AesCipher import ECB
from AesCipher import CTR

# Szyfrowanie ECB
textECB = 'Ala ma kota.'
ECB().encrypt(textECB)

# Odszyfrowanie ECB
keyECB = 'd6860664070b04efa7942c3ab033bce7'
textECB = 'd1386f2e0f43a85f3a2965a3713e7823c0e89d3103195460663c108ede8902a6a501bd3f25b787d78d7414798219e1c0ac25904d1fe5f00319b5adbb1d21f66d2ba339b104244df814e8e7e89577fb2081b23654dd4836ff2f597f0458ef1dc0d4c088b4e6256dfcc75076b4b1b2aa2b666239c6705c59266f6a0be0891c17c90150b7ee0aad23e76af3effa4cc46fd0af5771f7098d7fa6a420fd7203d4866b9c2f4a8e84f1cc7678f8af44c24d13cefd51acea49e1cc3ce69b92725c8a20812377c41141c9f2782835ab95d367783b28c31c85afbfa13e340f45b0c590cce70bdb814c7edc9017dda349c4f977146b52f70177d029de084d3dc9beaf5479e6231a4a12233e3046a4020d778b209568966c9bcad604f1a8fbcb7ceed7453049d2b7e9d1c8e4128f5852d670bec2d5da220d89a2001946fc6bfe0a0158f957f0551feb024d88e92784e7a8da21e31ae8ab9e67e0fd23ccb24654a2d1b07c5dcd8c34305a744f828ef88f63d8a26e0a09c9bed53f9fc547346c07cc601cde70b7'
decryptedTextECB = ECB().decrypt(keyECB, textECB)
print "ECB_DECRYPT - Odszyfrowana wiadomosc: " + decryptedTextECB

# Szyfrowanie CBC
textCBC = 'Ala ma kota.'
CBC().encrypt(textCBC)

# Odszyfrowanie CBC
keyCBC = '73407480b3a806fc725ffb4b03f5c7c6'
initialVectorCBC = '19452a4d0193d2baee5d5417f65c4e4a'
textCBC = '924ea52f2b01fb365901b6219c59142131c0ab7d62fb351214a62b8ded3ab6e8fcc1008b68b8d18bf2877f151c5959f277c62e9207690d536c4a2115d22fa968e9fdec16b40c3fc48d5012130f8855efec67144b1592dde7a871f08d2ab8b18cce1d6b30aecf1281085150968ba422f45234101a00b478c3a64297d029783f02a9747893abb335757d786b3204091b5c75b597c01475956a7f9b3fa0488055bcddb527f7d115c19970b5a194dea60f319707c47aad6a1f90d02f1fe93be0d562990c0a23add229fb9bbce16aacff980c22c2d6d0d90c52c511aa6b2ed9c19ace833146b797d45b9be315ea8270693020005e09ca4169a2ba7e6f0d308995e5bd'
decryptedTextCBC = CBC().decrypt(keyCBC, initialVectorCBC, textCBC)
print "CBC_DECRYPT - Odszyfrowana wiadomosc: " + decryptedTextCBC

# Szyfrowanie CTR
textCTR = 'Ala ma kota.'
CTR().encrypt(textCTR)

# Odszyfrowanie CTR
keyCTR = 'd1ac6bfa57eecc32d702ebff12593ef6'
initialVectorCTR = '234076d6afeb5eb7eb5a21d38d66216b'
textCTR = '90990241c07b887ff0900c874c196cd581c7c120448603d65e0e55eccaffdab221c0dcdf9585c8315abbf668f5ebbf04e534cd5b28cad951d53e9ce44dbd99e01411f359c9788f47f534ad85931b4cdc162011a9469032854588367d36fb69d515bd05fe47335d27861abd726fbe983928672c18cbe2d245d647df538e62b4f7df8c72bbec5e386cc3765d1d89183fa098b5c4fd3f81677951ed3a8af6427af5c03a4533113e7a0e817ea343f931963ac4102de79e8c89f5eeb815bcad9ab6bac35e47d3397c641e66ad5f3000bfbaa4acd38b4c'
decryptedTextCTR = CTR().decrypt(keyCTR, initialVectorCTR, textCTR)
print "CTR_DECRYPT - Odszyfrowana wiadomosc: " + decryptedTextCTR
