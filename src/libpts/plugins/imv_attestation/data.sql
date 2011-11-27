/* Products */

INSERT INTO products (
  name
) VALUES (
 'Ubuntu 11.04 i686'
);

INSERT INTO products (
  name
) VALUES (
 'Ubuntu 11.04 x86_64'
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

INSERT INTO products (
  name
) VALUES (
 'Gentoo Base System release 1.12.11.1 i686'
);

INSERT INTO products (
  name
) VALUES (
 'Ubuntu 11.10 i686'
);

/* Files */

INSERT INTO files (			/* 1 */
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

INSERT INTO files (			/* 5 */
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

INSERT INTO files (			/* 10 */
  type, path
) VALUES (
  0, 'libxt_esp.so'
);

INSERT INTO files (
  type, path
) VALUES (
  0, 'libxt_policy.so'
);

INSERT INTO files (
  type, path
) VALUES (
  0, 'libxt_conntrack.so'
);

INSERT INTO files (
  type, path
) VALUES (
  0, 'libipt_SNAT.so'
);

INSERT INTO files (
  type, path
) VALUES (
  0, 'libipt_DNAT.so'
);

INSERT INTO files (			/* 15 */
  type, path
) VALUES (
  0, 'libipt_MASQUERADE.so'
);

INSERT INTO files (
  type, path
) VALUES (
  0, 'libipt_LOG.so'
);

INSERT INTO files (
  type, path
) VALUES (
  0, '/sbin/ip6tables'
);

INSERT INTO files (
  type, path
) VALUES (
  0, 'libip6t_LOG.so'
);

INSERT INTO files (
  type, path
) VALUES (
  0, 'libxt_mark.so'
);

INSERT INTO files (			/* 20 */
  type, path
) VALUES (
  0, 'libxt_MARK.so'
);

INSERT INTO files (
  type, path
) VALUES (
  1, '/lib/iptables'
);

INSERT INTO files (
  type, path
) VALUES (
  0, '/etc/tnc_config'
);

/* Product-File */

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  1, 1, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  1, 4, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  1, 5, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  1, 7, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  1, 17, 1
);

INSERT INTO product_file (
  product, file, metadata
) VALUES (
  1, 22, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  2, 2, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  2, 4, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  2, 5, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  2, 7, 1
);

INSERT INTO product_file (
  product, file, metadata
) VALUES (
  2, 22, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  3, 3, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  3, 4, 1
);

INSERT INTO product_file (
  product, file, metadata
) VALUES (
  3, 22, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  4, 3, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  4, 4, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  4, 6, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  4, 7, 1
);

INSERT INTO product_file (
  product, file, metadata
) VALUES (
  4, 22, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  5, 3, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  5, 4, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  5, 6, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  5, 7, 1
);

INSERT INTO product_file (
  product, file, metadata
) VALUES (
  5, 22, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  6, 3, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  6, 4, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  6, 17, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  6, 21, 1
);

INSERT INTO product_file (
  product, file, metadata
) VALUES (
  6, 22, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  7, 1, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  7, 4, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  7, 5, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  7, 7, 1
);

INSERT INTO product_file (
  product, file, measurement
) VALUES (
  7, 17, 1
);

INSERT INTO product_file (
  product, file, metadata
) VALUES (
  7, 22, 1
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
  1, 7, 32768, X'40763935cdea25119002c42f984b994d8d2a6d75'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  1, 7, 16384, X'27c4f867d3f994a361e0b25d7846b3698d29f82b38662f233a97cafc60c44189'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  1, 7, 8192, X'301dad8829308f5a68c603a87bf961b91365f0346ac2f322de3ddcbb4645f56c0e6d2dc503ec2abff8fe8e895ce9304d'
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
  3, 6, 32768, X'91f4bb52404ca26b3a797152076ca5d233b93c1d'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  3, 6, 16384, X'59bced619eabbde5dd3ef74b92ba660349e105d36be9756c8d1598abd4bc066c'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  3, 6, 8192, X'fc6b1350067d23fca711b8a674e0367ad255bae0ddb2efe10dca1b18b18985bd09a7459937fda729d349874bb2701df3'
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
  4, 6, 32768, X'e3cf3ef2ee5df0117972808bfa93b7795f5da873'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 6, 16384, X'fde81f544e49c44aabe0e312a00a7f8af01a0e3123dc5c54c65e3e78ba475b22'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 6, 8192, X'e0cc89d1f229f9f35109bef3b163badc0941ca0a957d09e397a8d06e2b32e737f1f1135ebf0c0546d3d4c5354aaca40f'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 7, 32768, X'ff6deca0eeb7a257205c5f0ab5f5d821ea184098'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 7, 16384, X'5c84fdf7c529d3c65a001587eda641fe489f83961a621fe514e7852a842690d6'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  4, 7, 8192, X'8bd699f85f5b3efb27204b4699c518f871ef245d03b4bf8d1cc00456025017546030c2f493525754cffcd24cdbc03b21'
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
  5, 7, 32768, X'7a3ca72158e60b0c91e48a420848f1b693aea26c'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  5, 7, 16384, X'f9693c7d36c087d51f5012897fa0e8bb94081854d080c84f831f4d693d22f645'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  5, 7, 8192, X'4ec135e54c8840ab575fcdf00c66f996f763863ad30800b0f0a0b02e7899697d6ab9ccfe185ccbc16c19f38d0a27becb'
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
  8, 7, 7, 32768, X'11ce3b45feb3e66a75490d42ba95071ac6f40a7f'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 7, 7, 16384, X'468ef70f19372bc4a2b1805ffa3621515061fc19fa361374788bd362d638ac02'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 7, 7, 8192, X'63076ae505ce52c37878c9b6891ac516320046403aec25bf347c7011c2d28d5db7e2946d1fae3006ab4ef43716ff4558'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 21, 6, 32768, X'010873de0d682a26e1c6795dd4992248cc47cdd1'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 21, 6, 16384, X'bfb45524d81a3645bf216a6cf52cd5624aadf6717012bf722afce2db3e31f712'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  8, 21, 6, 8192, X'f69b3f60b904f2deb39ea1fb9b0132638f0aea27357e365297f6b2ec895d42b260143b5e912d00df1a4a1d75a1b508fa'
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

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 7, 32768, X'1d740abd38f9f4bc81ca434a0e25b6e21704248b'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 7, 16384, X'e26bb7175956dc8747a81431e810f830413b6c63756bf5156ab51367fe4f48a0'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 7, 7, 8192, X'5d3637413b9e318d0e0be6a9da86121062b99d1bdb084dfda4222baa71b250de644b4024281760b4eae926e03fac4fdb'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 21, 6, 32768, X'e1df4f3949b09c25e15b9c9b7088a60d683903a8'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 21, 6, 16384, X'46f0ec6b0a2c3a24157019ed60f03de2ec9160d07f12b7e0b3d3f02b609a151d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  9, 21, 6, 8192, X'4f73eae305e01e9ad57b5b1271a16bb8518fb82135aeb27311aa390d0d3a564b596adb723137f15bbf1db38b8dcbbdae'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 7, 1, 32768, X'339a58a1b313830c3cc74cb3fb52a5b8152f44e6'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 7, 1, 16384, X'789f2c6a9382bb342964a12947ddf84735d3e3ed3aefbae407098738cdf7c686'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 7, 1, 8192, X'858310a6e4b6311c491c4370990bfd6b9f03a49bb5ddf45b0d788f7043f130016e11be6bd95db66e49e2906a87adf8cb'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 7, 7, 32768, X'339a58a1b313830c3cc74cb3fb52a5b8152f44e6'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 7, 7, 16384, X'789f2c6a9382bb342964a12947ddf84735d3e3ed3aefbae407098738cdf7c686'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 7, 7, 8192, X'858310a6e4b6311c491c4370990bfd6b9f03a49bb5ddf45b0d788f7043f130016e11be6bd95db66e49e2906a87adf8cb'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 21, 6, 32768, X'87df2d01b85d8354819b431bae0a0a65bfc5d2db'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 21, 6, 16384, X'a25fef11c899d826ea61996f0bc05330bc88428eafb792be0182ad97b6283aae'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  10, 21, 6, 8192, X'357e5756dbfa22c21d3666521e644eefdf532b7d371cca62fc099579f3c98b97cb51d005dcbaf805f8a7def26dfde142'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  11, 7, 1, 32768, X'2d32ef93126abf8c660d57c67e5076c6394cabe8'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  11, 7, 1, 16384, X'ced29aca7fc2dd0b01d5d544dfb2e1640a6a79c657f589e7dd6636cfd63eda3b'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  11, 7, 1, 8192, X'a2d33fa2d0ee7bffa5e628f88ccb83cd61bb4c5fe6d2edb8b853b83d8c43f498fa6e8da70510f0a1a3ddb36060bbd4d8'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  11, 7, 7, 32768, X'2d32ef93126abf8c660d57c67e5076c6394cabe8'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  11, 7, 7, 16384, X'ced29aca7fc2dd0b01d5d544dfb2e1640a6a79c657f589e7dd6636cfd63eda3b'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  11, 7, 7, 8192, X'a2d33fa2d0ee7bffa5e628f88ccb83cd61bb4c5fe6d2edb8b853b83d8c43f498fa6e8da70510f0a1a3ddb36060bbd4d8'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  12, 7, 1, 32768, X'6c0b2df4fc4c9122b5762ae140d53fdd1cf9e89b'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  12, 7, 1, 16384, X'53c3f2bd5aaf8ef4c40f9af92a67621f5e67840b5ff2db67d1bccbcb56f7eef1'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  12, 7, 1, 8192, X'1a4a6d91bda3ce59e6c444ccc1e758c9c6f0e223fd8c5aac369260cdfa83081c0e8f3753f100490910ec161902f10ba7'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  12, 7, 7, 32768, X'6c0b2df4fc4c9122b5762ae140d53fdd1cf9e89b'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  12, 7, 7, 16384, X'53c3f2bd5aaf8ef4c40f9af92a67621f5e67840b5ff2db67d1bccbcb56f7eef1'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  12, 7, 7, 8192, X'1a4a6d91bda3ce59e6c444ccc1e758c9c6f0e223fd8c5aac369260cdfa83081c0e8f3753f100490910ec161902f10ba7'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  13, 7, 1, 32768, X'e2f7b92abda769f82796f57a29801870585dcea3'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  13, 7, 1, 16384, X'6d3fe67a040dbb469ef498b26cece45806cb7ca04787bba53b7ba1c18e2abd0a'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  13, 7, 1, 8192, X'014852b73cd3eabfa955b7bd56b269d5a0590a2770cf3d656b3d68dbad30884327fc81ff96c6f661c9c4189c3aefa346'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  13, 7, 7, 32768, X'e2f7b92abda769f82796f57a29801870585dcea3'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  13, 7, 7, 16384, X'6d3fe67a040dbb469ef498b26cece45806cb7ca04787bba53b7ba1c18e2abd0a'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  13, 7, 7, 8192, X'014852b73cd3eabfa955b7bd56b269d5a0590a2770cf3d656b3d68dbad30884327fc81ff96c6f661c9c4189c3aefa346'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  14, 7, 1, 32768, X'160d2b04d11eb225fb148615b699081869e15b6c'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  14, 7, 1, 16384, X'1f5a2ceae1418f9c1fbf51eb7d84f74d488908cde5931a5461746d1e24682a25'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  14, 7, 1, 8192, X'f701cb25b0e9a9f32d3bba9b274ca0e8838363d13b7283b842d6c9673442890e538127c3b64ca4b177de1d243b44cf0d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  14, 7, 7, 32768, X'160d2b04d11eb225fb148615b699081869e15b6c'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  14, 7, 7, 16384, X'1f5a2ceae1418f9c1fbf51eb7d84f74d488908cde5931a5461746d1e24682a25'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  14, 7, 7, 8192, X'f701cb25b0e9a9f32d3bba9b274ca0e8838363d13b7283b842d6c9673442890e538127c3b64ca4b177de1d243b44cf0d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  15, 7, 1, 32768, X'5a0d07ab036603a76759e5f61f7d04f2d3c056cc'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  15, 7, 1, 16384, X'85491714e860062c441ff50d93ad79350449596b89b2e409b513c2d883321c9d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  15, 7, 1, 8192, X'8038830a994c779bc200e844d8768280feca9dd5d58de6cd359b87cc68846799edfd16e36e83002da4bb309cfd3b353d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  15, 7, 7, 32768, X'5a0d07ab036603a76759e5f61f7d04f2d3c056cc'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  15, 7, 7, 16384, X'85491714e860062c441ff50d93ad79350449596b89b2e409b513c2d883321c9d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  15, 7, 7, 8192, X'8038830a994c779bc200e844d8768280feca9dd5d58de6cd359b87cc68846799edfd16e36e83002da4bb309cfd3b353d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  16, 7, 1, 32768, X'd6c8dfbaae7ab28b5cef2626a2af3f99a6ea4365'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  16, 7, 1, 16384, X'd0d6f784e937227cce99e3be860be078d0397a6fb5a5bc9d95a19ef855609dbc'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  16, 7, 1, 8192, X'4be6e7978a6e4fb8a792815f2bbe28c2e66276401fb98ca90e49a5c2f2c94a1c7aac635d501d35d1db0fd53a0cb9d0fa'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  16, 7, 7, 32768, X'd6c8dfbaae7ab28b5cef2626a2af3f99a6ea4365'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  16, 7, 7, 16384, X'd0d6f784e937227cce99e3be860be078d0397a6fb5a5bc9d95a19ef855609dbc'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  16, 7, 7, 8192, X'4be6e7978a6e4fb8a792815f2bbe28c2e66276401fb98ca90e49a5c2f2c94a1c7aac635d501d35d1db0fd53a0cb9d0fa'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 1, 32768, X'8a7c41167bc0fcc1dec8329a868ba265c23857f5'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 1, 16384, X'f8eb857d7bb850f44c15363ba699442c2810663ac5a83a5f49e06e0fd8144b0e'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 1, 8192, X'f40cb6e557ab18d70080e7995e3f96cc272842e822bf52bc1c59075313c2cd832f96cf03a8524905f3d3f7a61441c651'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 6, 32768, X'8178f18dcb836e7f7432c4ad568bfd66b7ef4a96'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 6, 16384, X'2d6aaed577bfac626ff4958ee1076bc343f8db46538aa6c381521bac94c5ca9e'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 6, 8192, X'747bbaee322f9bf1849308f8907e2a43868eae8559a7be718113abb4ce535f6d509d005e51788cf3e83e148487fe7bf3'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 7, 32768, X'8a7c41167bc0fcc1dec8329a868ba265c23857f5'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 7, 16384, X'f8eb857d7bb850f44c15363ba699442c2810663ac5a83a5f49e06e0fd8144b0e'
);

INSERT INTO file_hashes (
  file, product, algo, hash
) VALUES (
  17, 7, 8192, X'f40cb6e557ab18d70080e7995e3f96cc272842e822bf52bc1c59075313c2cd832f96cf03a8524905f3d3f7a61441c651'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  18, 7, 1, 32768, X'23296f48276e160b6d99b1b42a9114df720bb1ab'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  18, 7, 1, 16384, X'78cd0a598080e31453f477e8d8a12ec794e859f4076ed92e53d2053d6d16762c'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  18, 7, 1, 8192, X'4da3955f1fd968ecf95cff825d42715b544e577f28f411a020a270834235125bc0c8872bac8dd3466349ac8ab0aa2d74'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  18, 7, 7, 32768, X'23296f48276e160b6d99b1b42a9114df720bb1ab'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  18, 7, 7, 16384, X'78cd0a598080e31453f477e8d8a12ec794e859f4076ed92e53d2053d6d16762c'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  18, 7, 7, 8192, X'4da3955f1fd968ecf95cff825d42715b544e577f28f411a020a270834235125bc0c8872bac8dd3466349ac8ab0aa2d74'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  19, 7, 1, 32768, X'd537d437f058136eb3d7be517dbe7647b623c619'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  19, 7, 1, 16384, X'6a837037ad3fc4d06270d99cee2714dcf96b91aeb54d3483009219337961f834'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  19, 7, 1, 8192, X'7b5b16840da590a995fab23533f41982c5b136bff8e9b9a90b3c919a12cee20d312091455057a8bba9d9fbe314e6203d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  19, 7, 7, 32768, X'd537d437f058136eb3d7be517dbe7647b623c619'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  19, 7, 7, 16384, X'6a837037ad3fc4d06270d99cee2714dcf96b91aeb54d3483009219337961f834'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  19, 7, 7, 8192, X'7b5b16840da590a995fab23533f41982c5b136bff8e9b9a90b3c919a12cee20d312091455057a8bba9d9fbe314e6203d'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  20, 7, 1, 32768, X'f9e3531abb67a020cf667d46ca823675dd0a0dd4'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  20, 7, 1, 16384, X'569bafa2dabbcfa0ba9c7c411eacfeb8930f9d856a1a43cf8aa3662a67c13e35'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  20, 7, 1, 8192, X'84200bd318bb022915150842ddf4002e061ef593604ad0d07021dc662cc40bfa749cce084ddf25d0e5137f6380f613d8'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  20, 7, 7, 32768, X'f9e3531abb67a020cf667d46ca823675dd0a0dd4'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  20, 7, 7, 16384, X'569bafa2dabbcfa0ba9c7c411eacfeb8930f9d856a1a43cf8aa3662a67c13e35'
);

INSERT INTO file_hashes (
  file, directory, product, algo, hash
) VALUES (
  20, 7, 7, 8192, X'84200bd318bb022915150842ddf4002e061ef593604ad0d07021dc662cc40bfa749cce084ddf25d0e5137f6380f613d8'
);

/* AIKs */

INSERT INTO keys (
  keyid, owner
) VALUES (
  X'b772a6730776b9f028e5adfccd40b55c320a13b6', 'Andreas, merthyr (Fujitsu Siemens Lifebook S6420)'
);

/* Components */

INSERT INTO components (
  vendor_id, name, qualifier
) VALUES (
  36906, 1, 33  /* ITA TGRUB */
);

INSERT INTO components (
  vendor_id, name, qualifier
) VALUES (
  36906, 2, 33  /* ITA TBOOT */
);

INSERT INTO components (
  vendor_id, name, qualifier
) VALUES (
  36906, 3, 33  /* ITA IMA */
);

/* AIK Component */

INSERT INTO key_component (
  key, component, depth, seq_no
) VALUES (
  2, 2, 0, 1
);

INSERT INTO key_component (
  key, component, depth, seq_no
) VALUES (
  1, 3, 0, 1
);

INSERT INTO key_component (
  key, component, depth, seq_no
) VALUES (
  1, 2, 0, 2
);

/* Component Hashes */

/* ITA TBOOT Functional Component */

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  2, 2, 1, 17, 32768, X'9704353630674bfe21b86b64a7b0f99c297cf902'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  2, 2, 2, 18, 32768, X'8397d8048ee36d7955e38da16fc33e86ef61d6b0'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  2, 1, 1, 17, 32768, X'd537d437f058136eb3d7be517dbe7647b623c619'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  2, 1, 2, 18, 32768, X'160d2b04d11eb225fb148615b699081869e15b6c'
);

/* ITA IMA Functional Component */

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  1, 0, 32768, X'4d894eef0ae7cb124740df4f6c5c35aa0fe7dae8'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  2, 0, 32768, X'f2c846e7f335f7b9e9dd0a44f48c48e1986750c7'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  3, 0, 32768, X'db0b68f3ad06b5c0c35deb56af22b8f0bc23ea50'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  4, 0, 32768, X'a662680c8564f92cf20c5857d781ed3f0806da5d'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  5, 0, 32768, X'10bfa817da3a9e5760fbe78f216502e8ca4f94ef'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  6, 0, 32768, X'd0e1af1be845f570e44612613c4ddf3f08996151'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  7, 0, 32768, X'f05553c39e8130c7bb5db6cd6a6bf627311a9b01'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  8, 0, 32768, X'96ef1ad4efc5be2b894a12e5bffddcd496044a08'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1,  9, 0, 32768, X'e9055f2050b99b9127b6feef3164cb8ead8eb2eb'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 10, 0, 32768, X'6f8150aa3423544ea59ea10025993e660568cc08'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 11, 0, 32768, X'f843e55c9061fec89f2aeb369a74b73fe8eb09e4'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 12, 0, 32768, X'1d1efd1cb89be96f8fdf20ee0b67a89670659208'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 13, 0, 32768, X'f907598ec6fcc5779ff9091ba0925c1d58500352'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 14, 0, 32768, X'42f32d6fba099b0eea2e9a480dc8d4482e20412e'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 15, 0, 32768, X'e8a7cd52522ebacf4637a2b875494cda1c26bd8c'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 16, 0, 32768, X'd62d2c550fd06cae76f3e9c4d63f5fc22e34d4fe'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 17, 0, 32768, X'dc1293a87cab43024a4eaeb684a0186e33dacfe3'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 18, 0, 32768, X'03df488f642a9614ed718bf149fb7289d124189a'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 19, 0, 32768, X'46f1426433c57ee44b5593584308f8b7ac414e17'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 20, 0, 32768, X'1a837850cff01cd311948abd611174fa5699804b'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 21, 0, 32768, X'1c15052b28ac97e6e1cd0b4671fe75607c07de02'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 22, 0, 32768, X'1839bc8b6cd9351565a6bacb57f0e35562962cba'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 23, 0, 32768, X'f428189580a77b142b3de6cd3c183cb0a24dba6f'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 24, 0, 32768, X'f9b7302c9212a5398057ddea9c7506b265c3276f'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 25, 0, 32768, X'3af5d2929b9606b94b404a45deed9a9d673f49b7'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 26, 0, 32768, X'51a7df78bd7a23399b2824ec053f2abe5e4ee049'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 27, 0, 32768, X'2a3675f5efce9151670e9d4ec41e2edf4708d336'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 28, 0, 32768, X'a0cc14b4fde29d7251673af434b2ab246e5acf5a'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 29, 0, 32768, X'5932b35ba45894e65d6aa1afbe2101f677e17000'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 30, 0, 32768, X'ee12ad673d19d8f436ea7832e64935a0ddf9930e'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 31, 0, 32768, X'7bd9b4947ae9b600e6a2d61ead80104d878bb9d2'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 32, 0, 32768, X'849c60fc7b366717aea2295a37b341e40626dd28'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 33, 0, 32768, X'cdd448834760041cc30edd09f41ae36cbf9459ef'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 34, 0, 32768, X'9471225809633ae61f2693711cd878ba2ac59ef9'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 35, 0, 32768, X'4aaa26a4d1389b2400138269d3415bb492cc4312'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 36, 0, 32768, X'a08b0c957c8f741e273e8aa9a88d87b32b860228'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 37, 0, 32768, X'7ecbc26a2272256969e4c626998570c7e013be9c'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 38, 0, 32768, X'12dcf52c5a92b64dd5113031379f27b9f42d5c49'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 39, 0, 32768, X'ca1b8cc8e8ee8b209fc7b55656c3f6ac0b8f86fd'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 40, 0, 32768, X'8566865ae43d19574e85f9f3b6376715ffb3c707'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 41, 0, 32768, X'39c9fda07d57fc185b37bac70ba1068d6e7c41d3'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 42, 0, 32768, X'96a2c8b6caf11da5a37b41706217d4e94bb627c0'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 43, 0, 32768, X'6ee8c5a500af82a1fdf42e5122196fad4f2bbc06'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 44, 0, 32768, X'd2f71dff59d0ab86d0ada6ea288227602d6cf371'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 45, 0, 32768, X'095c8df0b106947e2c62a4458b13f38c6fc4f982'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 46, 0, 32768, X'706071d37157e1030900df60e6efaf897fbab1ec'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 47, 0, 32768, X'97f093c5ab5e2baf9b6f1473b631d3db2595fe99'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 48, 0, 32768, X'c12dd08ffbb4c09e3c282dd7f94cdcc9148ab866'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 49, 0, 32768, X'fb3df3be6d847db26e07eb61312bdc533bda53d2'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 50, 0, 32768, X'88195da5656b80c68bd3e131fb673b197281c2b0'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 51, 0, 32768, X'28353744f0fab757b1a870de007b6c8821d4723e'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 52, 0, 32768, X'9338b619160d4fb1a844acc95b0556b3d6109a77'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 53, 0, 32768, X'cd7f42895c6e4f9752f8b34184059d7ad4e5e6ce'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 54, 0, 32768, X'da5611278bf6855a44e5b1b5d62c76822a81674d'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 55, 0, 32768, X'eb4148c57806114b755416ba96b282fcc99ac2d1'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 56, 0, 32768, X'5e05f61508a391480dc83f741920a5de059546bc'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 57, 0, 32768, X'a23b279883915b0dc3313081924366ea5e75bdc1'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 58, 2, 32768, X'ef7511b5248557ae637f46b552f8af59020f2b00'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 59, 2, 32768, X'6240c588a2d7740f5c2c9523bff7d98334998d77'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 60, 2, 32768, X'808ce28868d844d547e0c2cc4271c14be2a568b6'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 61, 2, 32768, X'd736a206033ecbefc09e909f0d2d72c38d49d50b'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 62, 2, 32768, X'387a7087c3159f7d0a6388d722c200a599b4703b'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 63, 2, 32768, X'b6a679dda488042eee3cf9a525a9ae88b9514229'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 64, 2, 32768, X'693b89dc96682f85b389208ec052f4853fd971eb'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 65, 2, 32768, X'e4b83a6888c69eeb1c65c7ff50ee39897ca51008'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 66, 2, 32768, X'9e0735ad94f4d10faa43f75d02c4edb9b7eb91d4'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 67, 2, 32768, X'881dd3cb2f1f0e3323bf8c5586dfaba2ffcb1a55'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 68, 2, 32768, X'6461d3771999c3a4b3c15bf4e38da30b91bc1b17'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 69, 6, 32768, X'fcad787f7771637d659638d92b5eee9385b3d7b9'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 70, 0, 32768, X'4b90d9178efc5cf9a9ddf4f8bcc49008785d76ec'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 71, 2, 32768, X'e79e468b1921b2293a80c5917efa6a45c379e810'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 72, 2, 32768, X'be1bdec0aa74b4dcb079943e70528096cca985f8'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 73, 2, 32768, X'bc3a1d50aaffa207d2e6645228bb4f1cd40c88e0'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 74, 2, 32768, X'96ea8b0ccfb43fa6da4e98d8f51609cf8eabd91e'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 75, 2, 32768, X'd05ef7250cc103540601fb8956c89c3ba1f47a4e'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 76, 2, 32768, X'd5c28da6b58a66fba125e99c6b6d0e36a1b18315'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 77, 2, 32768, X'0ba611dd45de9acbe3d0da0d2e478e4aa77ff515'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 78, 4, 32768, X'9b4d80cfefc7d5576c4d9f224872505896ef2798'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 79, 2, 32768, X'e79e468b1921b2293a80c5917efa6a45c379e810'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 80, 2, 32768, X'be1bdec0aa74b4dcb079943e70528096cca985f8'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 81, 2, 32768, X'e79e468b1921b2293a80c5917efa6a45c379e810'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 82, 2, 32768, X'be1bdec0aa74b4dcb079943e70528096cca985f8'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 83, 1, 32768, X'230b3bf13c752834decf47f5a86a75582abee51c'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 84, 1, 32768, X'61f59f7782bb39610dbb6b1f57033c161810a267'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 85, 1, 32768, X'c744cac6af7621524fc3a2b0a9a135a32b33c81b'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 86, 1, 32768, X'8a7532af1862f9f61ed08d2b92b82a2ecc99c54f'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 87, 1, 32768, X'ba8fa710d303b3b2a594cba1cb73797c970ffa0b'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 88, 1, 32768, X'a46c5c8b58e67fbe9d3203bae335c0e39f68eff9'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 89, 1, 32768, X'67476198f63603b84afa235970611cd614560cf2'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 90, 2, 32768, X'cdf4d79ac0a10d46a1d9d7ec9642883c71f77fc7'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 91, 2, 32768, X'436067385bf6cd43e2f65f8d70d264af8fca876d'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 92, 2, 32768, X'4916c4e9f1e91b34bd8acef1f827f0b444bdb858'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 93, 2, 32768, X'c66007c47ea62816006d220bbb8fc9d5681c4cc6'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 94, 2, 32768, X'85782c59534d3915298da3da35101891a84be99e'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 95, 2, 32768, X'335f1897c44fef511bed7eb4394375bc2a36dbc3'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 96, 2, 32768, X'82ca255a4c2655eca1516b4249dcdd1edb892eef'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 97, 2, 32768, X'1086445009abbad955b9e915be04ac9afc74567d'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 98, 2, 32768, X'18fe7ae42869e2b3b11bf67215ef4f1c2e260251'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 99, 2, 32768, X'061efe921cad309990e63ed35a7b833e2eabfd2f'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 100, 2, 32768, X'aab5803005883807e91538fdc71968edf81f367c'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 101, 2, 32768, X'aab5803005883807e91538fdc71968edf81f367c'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 102, 2, 32768, X'0ba199b3cd6991a884fe30f40e89d3d603aa5cbd'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 103, 2, 32768, X'0ba199b3cd6991a884fe30f40e89d3d603aa5cbd'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 104, 2, 32768, X'2a5aa44e77a223d701a53b0f9af6d13cf8443b2a'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 105, 2, 32768, X'2a5aa44e77a223d701a53b0f9af6d13cf8443b2a'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 106, 2, 32768, X'c32ab71e81421207255b2665316a9049ddff3653'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 107, 2, 32768, X'c32ab71e81421207255b2665316a9049ddff3653'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 108, 2, 32768, X'cafaeff88886bf0d07b0a6527341da22c08b609d'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 109, 2, 32768, X'cafaeff88886bf0d07b0a6527341da22c08b609d'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 110, 2, 32768, X'68d74b6eacdc3360615744c6aaddb357df9bdbec'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 111, 2, 32768, X'68d74b6eacdc3360615744c6aaddb357df9bdbec'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 112, 2, 32768, X'ac254b04f277ca7e887a4141bf5ed0cf62600d10'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 113, 2, 32768, X'ac254b04f277ca7e887a4141bf5ed0cf62600d10'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 114, 1, 32768, X'4f135c9ee49ca7fbfea079e5d6714802f0405407'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 115, 0, 32768, X'9069ca78e7450a285173431b3e52c5c25299e473'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 116, 1, 32768, X'9069ca78e7450a285173431b3e52c5c25299e473'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 117, 2, 32768, X'9069ca78e7450a285173431b3e52c5c25299e473'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 118, 3, 32768, X'9069ca78e7450a285173431b3e52c5c25299e473'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 119, 4, 32768, X'9069ca78e7450a285173431b3e52c5c25299e473'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 120, 5, 32768, X'9069ca78e7450a285173431b3e52c5c25299e473'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 121, 6, 32768, X'9069ca78e7450a285173431b3e52c5c25299e473'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 122, 7, 32768, X'9069ca78e7450a285173431b3e52c5c25299e473'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 123, 4, 32768, X'c1e25c3f6b0dc78d57296aa2870ca6f782ccf80f'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 124, 4, 32768, X'67a0a98bc4d6321142895a4d938b342f6959c1a9'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 125, 4, 32768, X'06d60b3a0dee9bb9beb2f0b04aff2e75bd1d2860'
);

INSERT INTO component_hashes (
  component, key, seq_no, pcr, algo, hash
) VALUES (
  3, 1, 126, 5, 32768, X'1b87003b6c7d90483713c90100cca3e62392b9bc'
);

