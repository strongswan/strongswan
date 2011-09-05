/* Products */

INSERT INTO products (
  name
) VALUES (
 'Ubuntu 11.4 i686'
);

INSERT INTO products (
  name
) VALUES (
 'Ubuntu 11.4 x86_64'
);

INSERT INTO products (
  name
) VALUES (
 'CentOS release 5.6 (Final) x86_64'
);

INSERT INTO products (
  name
) VALUES (
 'Ubuntu 10.10 x86_64'
);

INSERT INTO products (
  name
) VALUES (
 'Ubuntu 10.10 i686'
);

/* Files */

INSERT INTO files (
  type, path
 ) VALUES (
  0, '/lib/i386-linux-gnu/libdl.so.2'
);

INSERT INTO files (
  type, path
 ) VALUES (
  0, '/lib/x86_64-linux-gnu/libdl.so.2'
);

INSERT INTO files (
  type, path
 ) VALUES (
  0, '/lib/libdl.so.2'
);

INSERT INTO files (
  type, path
 ) VALUES (
  0, '/sbin/iptables'
);

INSERT INTO files (
  type, path
 ) VALUES (
  0, '/lib/libxtables.so.5'
);

INSERT INTO files (
  type, path
 ) VALUES (
  0, '/lib/libxtables.so.2'
);

INSERT INTO files (
  type, path
 ) VALUES (
  1, '/lib/xtables/'
);

INSERT INTO files (
  type, path
 ) VALUES (
  0, 'libxt_udp.so'
);

INSERT INTO files (
  type, path
 ) VALUES (
  0, 'libxt_tcp.so'
);

/* Product-File */

INSERT INTO product_file (
  product, file
) VALUES (
  1, 1
);

INSERT INTO product_file (
  product, file
) VALUES (
  1, 4
);

INSERT INTO product_file (
  product, file
) VALUES (
  1, 5
);

INSERT INTO product_file (
  product, file
) VALUES (
  1, 7
);

INSERT INTO product_file (
  product, file
) VALUES (
  2, 2
);

INSERT INTO product_file (
  product, file
) VALUES (
  2, 4
);

INSERT INTO product_file (
  product, file
) VALUES (
  2, 5
);

INSERT INTO product_file (
  product, file
) VALUES (
  2, 7
);

INSERT INTO product_file (
  product, file
) VALUES (
  3, 3
);

INSERT INTO product_file (
  product, file
) VALUES (
  3, 4
);

INSERT INTO product_file (
  product, file
) VALUES (
  4, 3
);

INSERT INTO product_file (
  product, file
) VALUES (
  4, 4
);

INSERT INTO product_file (
  product, file
) VALUES (
  4, 6
);

INSERT INTO product_file (
  product, file
) VALUES (
  4, 7
);

INSERT INTO product_file (
  product, file
) VALUES (
  5, 3
);

INSERT INTO product_file (
  product, file
) VALUES (
  5, 4
);

INSERT INTO product_file (
  product, file
) VALUES (
  5, 6
);

INSERT INTO product_file (
  product, file
) VALUES (
  5, 7
);

/* File Hashes */

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  1, 1, 32768, X'409bb1a97e26ea1144cdd6801b8159f17f376b8f'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  1, 1, 16384, X'675172775cfd2b73ed1e249e4a730921f06c2f86fffdce4c71674cc654f37ed7'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  1, 1, 8192, X'abc8ce3fc99b6dcec6745ffc2f59e35372b9b126491480d04b0f93076beded06cccb27b61f1170868fada8cddefa7be4'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  2, 2, 32768, X'2a4047437e6fb346e2d854fc415e16b80e75bf6b'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  2, 2, 16384, X'86aa0bf93dade999277d963338402ed437271f3436f594a49ffca85b6c487523'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  2, 2, 8192, X'6090441219c0b478d294ae88e006d85ac0d94464573bcca7d180618a612bd170e3ee47c1545861b0f06fe0db85544c59'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  3, 3, 32768, X'07d8c0218a5b3469b409dc95cf8f77a341a595fb'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  3, 3, 16384, X'b083699fbc4c9f9e0d463361118904a3832670ad2fe3d6b42f811061188d509f'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  3, 3, 8192, X'b14908de476467a11a7a98835d1cf8317c7b80a684692426ddd7b0014e00b70b3d1b4fc1dd02ad440447612ee9dadb52'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  3, 4, 32768, X'4350f082511c742cc05050d18a23d1da9fb09340'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  3, 4, 16384, X'f9e12408828b5842c45503342dc2af78bc74d701a19c5fd5483df0e203315e0a'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  3, 4, 8192, X'1a5ea36e4ab0cda550c0da2af6a62d9310981d2f170c9e75bff1770be2efb9ddccc451743ff4c3d76876364f19fdf8c1'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 1, 32768, X'ff6deca0eeb7a257205c5f0ab5f5d821ea184098'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 1, 16384, X'5c84fdf7c529d3c65a001587eda641fe489f83961a621fe514e7852a842690d6'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 1, 8192, X'8bd699f85f5b3efb27204b4699c518f871ef245d03b4bf8d1cc00456025017546030c2f493525754cffcd24cdbc03b21'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 2, 32768, X'1118805b490051637e93e592f4c71e0ee78a2422'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 2, 16384, X'5ea7229ebef5dc8f9fb2118676b773dd62cf89dc21657e3b8fbbcbc70ee24bd3'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 2, 8192, X'3b8da9e704e644eb7b196981624a2f6826c401d689e00ba47e42ff46351d27c6b9e91b1e8351ee01f66e5244b4c2a9b0'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 3, 32768, X'b5cd500ec15d6bfcae15e0af1dc121df7114b97d'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 3, 16384, X'b94f1cba12abb0ec79d207142526388ec0d127c4f2aad4a46a623a1f69bac84f'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 3, 8192, X'6663d66ff0e93b1b8a1edcdbe45d64834e29dc9c2b1d23126fd370a85b2c56da5cadcbc65b6e8afbb1e18bea8e413bd1'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 4, 32768, X'86c4463293859874243d8374f7f3ef60f44f9309'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 4, 16384, X'348b711f16ee9810738857c8ffbc54f8e16a393df8635cb29b02fc62daeefc14'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 4, 8192, X'0cb6b7d91148b1bb1b9333bc71de01509cb6d12c646a6756e6942647046286fbbca92b25dc1999e8f81be1264061ee4d'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  5, 1, 32768, X'7a3ca72158e60b0c91e48a420848f1b693aea26c'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  5, 1, 16384, X'f9693c7d36c087d51f5012897fa0e8bb94081854d080c84f831f4d693d22f645'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  5, 1, 8192, X'4ec135e54c8840ab575fcdf00c66f996f763863ad30800b0f0a0b02e7899697d6ab9ccfe185ccbc16c19f38d0a27becb'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  5, 2, 32768, X'5d36a26856021d68a42f8bd7ca22365579d43891'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  5, 2, 16384, X'411be0558ad0cef33b437dafeed40104917e2079646524145abf9d05ddc6c1c5'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  5, 2, 8192, X'237f4691f9b780bec7aff217d64a9780ceed2973a41e86c92e0d6dab81cc5d13a9b99ba408302264f5665de1f42ef6e1'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  6, 4, 32768, X'92e66ae282947f66544682039a33fd1dbd402244'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  6, 4, 16384, X'dc6bad544f72c4538fb92f777646fd734b49ce95f41b2c96b74a21addbc86ed8'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  6, 4, 8192, X'08fd91f9017763212d1491f178e4d7e41d34a21b0117ee3321d832f5b8e02d4c7152a6cdc53bb4ca7e8aad5b1f279d1f'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 7, 1, 32768, X'11ce3b45feb3e66a75490d42ba95071ac6f40a7f'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 7, 1, 16384, X'468ef70f19372bc4a2b1805ffa3621515061fc19fa361374788bd362d638ac02'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 7, 1, 8192, X'63076ae505ce52c37878c9b6891ac516320046403aec25bf347c7011c2d28d5db7e2946d1fae3006ab4ef43716ff4558'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 7, 4, 32768, X'200eab67377bf3d5a25372838c38841658a718e4'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 7, 4, 16384, X'31045af9a12efdc58155a177e9391dd28b93fa38af58ce00f49259cc26e97687'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 7, 4, 8192, X'e8c64b508171d947069382da58dc7e39a97ce878a07f494a6fb370efb09116d32f1d4cdddeef85f22e14d1c5d5a37625'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 1, 32768, X'1d740abd38f9f4bc81ca434a0e25b6e21704248b'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 1, 16384, X'e26bb7175956dc8747a81431e810f830413b6c63756bf5156ab51367fe4f48a0'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 1, 8192, X'5d3637413b9e318d0e0be6a9da86121062b99d1bdb084dfda4222baa71b250de644b4024281760b4eae926e03fac4fdb'
);
INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 4, 32768, X'd2bf3556a0b38cfba2962d058fa8ea777397e82d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 4, 16384, X'4ec845e828af69dcbde3ecb981096ac1e25c9e3e607e9a24b27da7e44527edf9'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 4, 8192, X'3204a34ca409730298f60361865dace24900827ee9f3bc87884d50827911b4b17beb4c09bad77e43f28938f10bc5138a'
);
