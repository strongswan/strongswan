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

INSERT INTO files (
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

INSERT INTO files (
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

INSERT INTO files (
  type, path
 ) VALUES (
  0, 'libxt_MARK.so'
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
  1, 17
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

