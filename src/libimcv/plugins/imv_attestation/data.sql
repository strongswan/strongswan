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
  4, 5
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
  4, 163842, 32768, X'1118805b490051637e93e592f4c71e0ee78a2422'
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
