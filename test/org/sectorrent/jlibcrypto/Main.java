package org.sectorrent.jlibcrypto;

import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;

import static org.sectorrent.jlibcrypto.sphincs.Sphincs.*;

public class Main {

    public static void main(String[] args){
        byte[] pk = new byte[SPX_PK_BYTES];
        byte[] sk = new byte[SPX_SK_BYTES];
        byte[] seed = hexToBytes("133038bbb8225cc1a5bff68f704de766ddbd315b61cd7a66006cdb6b99a116f3df3be01d842391100e6c41a42ed126a7");
        cryptoSignSeedKeypair(pk, sk, seed);

        System.out.println(Arrays.equals(pk, hexToBytes("df3be01d842391100e6c41a42ed126a79e3297c818494f39a052021cf54c3979")));
        System.out.println(Arrays.equals(sk, hexToBytes("133038bbb8225cc1a5bff68f704de766ddbd315b61cd7a66006cdb6b99a116f3df3be01d842391100e6c41a42ed126a79e3297c818494f39a052021cf54c3979")));

        byte[] m = hexToBytes("133038bbb8225cc1a5bff68f704de766ddbd315b61cd7a66006cdb6b99a116f3df3be01d842391100e6c41a42ed126a7c55b35128b20476d1acd2c2a2891a3b266106d9b3541bb7818123af5ca0b79ee490c3cc9cef9a8e8c43f2141f563d8336924898e");
        byte[] signed = cryptoSign(m, sk);
        System.out.println(Arrays.equals(signed, hexToBytes("8f1a9fc6614f175242967edebf5e460239ad7c1d1c9962237cfa2487089604fc417f8f2efab6a6ff34d49ce1e7efea6def494d159253c01854f85a0a7808fcf0d81d886bc84fc55d78275b1c41c944d410e74120d7e95ddcb89ed9ed8f8c22b69408c9a3f62d49fadc407ee590151e9944dd8af21cdd9ec758ef4f26e0a35151f87dbafbd20378569cc48868a11a4f9821eb4fc901f6ae79b9c9f95fac5e8fe8dda42a4e3188a4c2fddeeb1b633eae554cd024db83f06ceb272ed8067c9c6e1295b9fa57d746bda4b3281ff416208dc44ea0303c0f28fdc812b09fd625255585054427dc5d084ecdc2db1abef87c56ed21029116f023ab04275bf4235162bfde470af3f7a20d046e4bd2b6a3953afa5ba17bbbe5555a54ae712c4745d7fba942a6f14ace00de5211791aea1a9810975361c85b134dffe27fb44b46e30556fecca195071a6003ee9d632f23233d20947ccf1f5614c68d45c615eefe59d60d2aa5bf722297a34eba721cb4e0243b373154d7b60d56511d5dcd579c9cb70a876d5bfbff105cb544934dc0a07573a1e4a131c9ef0801f31a9bea38bd565b09ad99f865d9e6838565bbc53e5ddc2b1455e22f0620da707b1de5dee02ca284baf7a6b6eaa6dd4f0a57f8f7f078ba6dd5a932ce208d6039229039ea2a181e4e2a553456a3b52eb501e912f731b5d682ff5f0469842c11d03c1675fe1ccf9b4358ce6db59c69c2297860dade22008d45cf398938e732be3074b5ae006c8f44e79c67ecefb2f2e4845ef11e8ce9c704209d17715132fd602ccabaee00661edb97b0efbcb24bc11c2c600b29355416fae4ddc8571f3c8e70c5d545bb5fa1c8e6a6d120e211c55e63290bcc083e7abf7a384a275e26ae0cd74dd0e7bb3e9df158cee653af7eebcc1afc47652f42610f238c94cb58adfc20068fe8778be6c1e611d7705f59092ddfab96525c8efc50a96511b8c3aec8702f3623ed337e46c04c471fc51850cc3ef3c243348132638292dae0202ed6e9105f3018aeba401859a66e83e7d9bcb5327acb0a571a3bdd28658c4906091ce42c52e9650f44e9c5ce5b6a1cf8ec9bd88b73d292e995c6fde00f14b90de4bc5db3e67d660bc18832918a1640ecb79823b6e914484d7388f384e4d715025013989d25410004cd814da644145d3f534c80cb768eb1ccb8a61f65bf9e3b3fcb49485420f38a872f3eb5dba39cc966c985feea0688133854cd92f44613e10b307d37dd77d7758cde5d38ca5cdb3a6ff5ea3b6f969b9a67b09d19503e60608b6355536e84b1be991c8b64b98fe98238a3f2aaae6fc73bd7a03a8cc47d42e267c1c449254bf601614cf2fa7f40a82e1ded2f14d3d64918c61ca3e0bae801d8ac827822e111a86947373be717785f7201c86dba83dc27fb7aac1467a86838211be7eef3fe14cf2c67d2d4290855602d5dc5eaa0efddce96a0298e178856f4e10cea45b6c34277246fb6ef8f8d352f2134f98bd97f890a5b8ecd573431d3aa910f5982b9155abdbe1f43266bd421cc3b669a3e2bc27a9c93f645948ca57dcd16b0ed8ef2e80e901b4a0e4562799825fa00b4ed063600133bea89be61770fe0c63d282963e14318d8e698c6316d1f26ad19bdd997f159e4f8dd002376adc9514cfec0b3c1f22a43fd624999fef841a7a956c7b4f0aab5af94300cd7e5628956b74a5e3f4c6d1da49fa737c977d6872390819c68642829535fe0fedb2cb612e28ef0116ae05530d55b7a75dfc680396731cfe892aaa313dc2c2f6b122d2449c8d509a4330983bf8a7b0424d48dfa21250061912f22995c715d1f5b359c380105c6c5ca1cc625d3e6ff50564f2fffaf77a84e4eb1b917b8cc3bcd1ab1ecc89d6c52ab59be5820671261efdbae5fccb04535f41ce161cc2f553270c13620263194b8bfa05b594fb81196d6c8cc3f0bced0dfe227093b281c20ce50b67e470ebae88458d229ca249b20a9cb194935e4c25c75421c25abfde2e42485136a6fe6ab5f4a9d532a26e70dfce23be8d4630e855358dde1730da3113cb4c7d168769f8c0be7867475ff2e0624e54751cf880b030ec3dd4e5d753afd6a3f737e8ea7a0adf7137857f68fece00d4b570d27d0018e7fff3d3f246e839a5c62315590e1c2373c2015a91b6af4a7fa967f321729ba4afe31e7218333b9db7fd439bc316c532b9f08be6001b0c9c32cf9a96dc9a62668a203092b6c78ee0858441f5e1c051d58997b92d3f14387835ca4493c53f863ba9156cb67b1023788bd286dd867c472da77449e133b78d641245bd46d5bcc5d1ccc282a6fcf538b9be3e70a556094cd1057c23dc9cf068ecebb042db223b15a93f3380d7de8579a56e41e9b1900cb5baa4452a7632cd89706be45fbb4b862375da787b03fefd097c83de364ffccc24580c20990e9741148f582dd4860f664c1ddc03b4aef65d76a146771de953fc310043a69bac10db0d2167a83123a1b4cc59afee16ab91fc2880f7d73dceaea2a718b1d90ed481f1f74efbc5c755b35412fcf40d5b955e39d4168ebeecfdeca4c1ea194c4b5e4f3761bddb75f006e5aa44ceb39d56477b24c7a11ff1c7f797db5d0f10c291aeb1dd2d33b666ec40bc33234d543c4357932494585725b491dbc2cf62619a3a28c7cb88d1707f67729591cd3d8881dfa55c58c074a3fbe49dfea5cf6aa84665c4dcf9e8c0ffd7743d803d0540b88939aa7e924f7d9c4d45b979b9e3b9d8093ca6e83c8435397d66c7e20a022c9530c6a3f7215452626e30946efc96bf17e759b53bd56cce58ba85484053b9535588be9e2d7d970c0de558df66da1640c1bff793ac5ba0d9a1d8d4cf1830b8d6c5cb3490e4a1a0525d34065408ffc01ec02c5d087157923698461497abfc8a029631aaf869cf6602d7c46cdb46f08de32d0abee89efd62464365097f32d30b2589a1b138d764b2eb0808d5040590da9f4c092e61b08b553e8b497abc750ed9efd0f49433dcbcbe04613f794026004a4327c01af0704b06c454f164cff19c18f513e37cb69beca129af610db7e05b6908f5f0a55a7f1ec0aa7a466e29c7f43f96c87efefb2141e41ff1845868ab9caa6f10c57175e2c0593d57329432db0469b9f80c972860f58ffc6e0548682516595f212dffa5863a32412fee02313718610eafdffde7b37a44b6ee28d8801219f4c09de31e3df6371763549e022fce8585251e6785f2186b1d338869c2859ef2f64331d0f0528503ad5d767a095c78d4cc0da01869fd1bf16d5d8587a38569e3246697249f8f5ce004772b0240aef69ee813ada1862a22e5834c74b58b31897eb259bae0d1f216edd90a7371870910a6464c0f71164624da62d264eb19aa37ebdc46d3ab7e36fba229779721a04c3e3b81cfbd091ee05ba0b0b1f38371a2cf75461b3dc4d856ffab9dacb9bf00a402f05ec047cd64705e37d64f8aaad960ae80e3626fcebb16c5c419a0cf32b505edcb769e4e29407b3275e8b8f44e8b0f896f8a38ea9a7072a6768ec23855bda0f50110fa7e75aa1b6959161d8dfc6c3f2159d55102c21812908513a39bb7905c82a64089b4cdcd6d7699225873d50634fe766999401924b8380f8cf1aad5728bd3c3b4560cfa90b6c3b57e73118fee3a49c84edfde9e52a29452721c31bfa61ddbec7e261a423999e7519259a766338248e45151bc3566688292ad72eb9bad78455069900de4d0ac38a8081f574291fad61516fda9f245d18cc6ee4533bbab21677d3f145c5e3de11593fda72af9fe471ed88dc53f5c6d80a6a0214f0144ae40e17e42864bfaaeed6cf17aca0c88dc24ff9bd4fdee73747101b9a41bedc92359a514bf396a450df4d46f0b3bb700b4c13ecceb346bdafd074e213b276325c3e3595f87ecaf9e12f5b1c52b86321ba31ba6b79637a18fcf84d2f683d0681a4ede55c383ffc6b4cc567fe1a6c9ee79d77ef312b9a0648a96cee7c13f5df9583b3a431fd4c9c7f996c3137dc3d993b115b48c4d8e9d67fa27cfc661487e197238370d2efb4dfba3f05c0d03f6ea83e4557378c0771ee1ab54a201444c149eb90d9068d42afd854fc052845fc35d0575587ccb6f102d07258e900ee7ad65533f857f13a71d54a9da2ddcffdae6c500d15a49d7e8cd17db21ac37f8227b077b7e9695c61019c6b7e4ddd846be1bd74df6c720f5e2b0bf5aa5802004b4daa52ada91fbff94fbff4919cfb8bc5757760e6cb5b235d82baa785d85249b4f26e3dbb9a340bcb1acd6ddcf3e1869d2cfb57bdb0f44257eee615f2066ac52ad2f7e0233cf8186bb0a0762e90e9a95a4a5c8cf89c82a728f9f9c806f77ec2b9b54ec8c2dc1a981beba6843bd7d4205fdf82aa1b448bd5082dd6bdf00e2a7fb85b640af998b82fdfa306fff8c8f3c732a5870534f35e5e915771b6d13005ed9816b55e696cc0eaf362fb1473cbee26ed9f03e1539c6bd0df2cba1e3195fbaf9e59c1ca0bd72eb3d062203d7593ce1dc3f09d60364855fe91f798f20a8957165d43987f586376b41aba0bf685f07a91d4187a23956dbab0f2446cff00ccfb8f7797da6a53208acaae782639035cb7e280fc096d11cc28e08c4d085b23ad38685a28a3ce175fec496d9fd56eebb7127857f754d7ffb75f130468bed96a4b9295adf66a6a37a89cc5bb00b0a502fa1160cf69c25ca52c5d0d3aefb06ccc4b2508cabe75593bd5a638e97c7573d3e1bac333fe94493d545e723b312c7d3b8f9c2b5ac6c8418207215bf4fac7e5d0fece89e5689df0cab2f45c0ef2bda9f09280f7bf1e31267523df5325b530f8577f4b44f1165111bce76415918069d0c336b00ba8f45c998547efc10c259140e54c537890ced887d69ebb13f989106203d2f0dbeb62a45d3a089a51b06ab675f883016719096bb77aff57ed7bcaabeef513d68d87bff664f0902fad46066a259abff908fe94140611a6b003fe239216cbdcb5ff2456e8dcd3c204a9d6953c82fa71c2bca488f624355433ace5f97e33bbbb37eda1181d798eaf157ed05fa23beeb420189f793004b4b509c2732fc631ddb52863eb781273b08c1e63a4a3c92d34a168d977bf63ed96180a7b106427e1e0409edb67d8965282ffa8ce7f4f4f1fca564aa3799c80055b4f7ef11a6e11cb1d083715fea5b85a7d8e1fc40e9b7f031bcebfb1275721b4951a33e5f344558f312c067b33a1fa56cbf41f23fe2b606d0cef65c6c82ca9bcc703b6bcc99616a348b6c366abaf16dffdba57efe0b5c5808a584d00f2200c350551c8874b6ec97de2bbe80104bfb5c1829feada3851e1351b45ebbf5360c88d3bb12ae76df15ba2aa183ef0cc3432d789189019dc1374850840e526eed4c794f3518307327c6c26e1d66371bf4d69ad72cd9b7502d50e4e35cb46e530a58ffed6294c43ecc3ee8bf814947d64f8bb7c7f042bcf25bc61883a9a7aa4f52b0a79b9f61f441348ba84395ba71c8bfaa8b011ffacba65955aa2de26d30dc30560c6ffe70457858f8e0a2c8905fdc429381418c39bb9afb7b13b801491c3d7ea7af650cf0f122e4f916eb7caa4be3afe71fa68d0c0f377155f2d7e80a4eec2160f2a1344f37618943ea1318821121e543c5a525c2d07ce862812daa5b96af64a80b1aabc8cf24b54ec05bb29b254419e952492546772f1ae8cef4efc33056fd76020cfa43cd07915c4419d3033703e601db46238bab92ffe3eafa83daaef4b3fed142e2b2bf62046da67dc54c96272c1a1f4739c30d8314391dea520de87e782b02b8e49cad5390d5b72179c8920448a44c0f39a45ad19fc074be15311ba3015f291695e7fa13b0c0da016cc93402075743c512fc1ee8a9a618cab280c1541b430930ef34203d15ef982944a9cd4a7084e9a515dbb3a8c0dfd0ec16763a39813e199718775b50788c02d20f97506db3a538826c4988c39af4ed25f4ae78724018f506bd12bc407dac34e344ec80bde9727cf9ccbe50b6905605cb68ac325054e7bdfddcde36ae52b0d4db571f0e9b79f85caea29408bd79eb4e7455f939b29a32ff03471cc06a01386f3c991ceb1259ae164b5b846c590ec7d6705c04584985117bb6e3bb8e3397523d92944a7413d3f6097e86db6102f14181ed61368c1cb3fc80972c7003c804a55f33a284f53f6703a6c145d9ee7f6e019a7a908023622a94e9845a071bca3a8ddb621d9906b8d2534ad3a2d8c5d6f2fd14954287a906c2341a1b7827499d320b025de10d662dbbd25a7d3ea811c1bd4a945f4ed0e75f035d1eb4741381d3445a5c36c65a2416c16bfacf0ada917cf33e49d7291ec2a5d1ffae8736424fb2280632e194b1c8caf5f429f42809c1ad5d79d29c7d42566d82670f53f73bfa81183827405ca834b0f4beca1cd9f7d563bdc4116e6d4c7cabd838ccdb9292f3e24d977d285dd8f4be8b0a9bb161d2f0b21b127e5c3db78f377baadadc939c4b8801707988db76a58efade25334436d3ba09ecbd1cae5db7ddcf9c2065e5153c6e80b40f4075c8df44a9ce2991751f7e8fa7b939a19fd3fd705c1681083c8ebbff47d108f4e4e09e9f009ab274bea282db0f0685cef1929f3a78b8c10d8f308541721fe1e97cac8bad207232c6cd92bb0e1d2d038bf0541f884115ef14f6aa953a22f729c147aca71a53a62bb53cf6f6f12ef7a196d175cdc9c4cef89180ea14d92851c33bf72443ce4aeb6495c643ed768ba55dfdb5794f3d73b6b64ce17ed9463ac620f9405b9dc6b94f2b5aaa9fa979983cf566defdda62b5796927515a48ac8e46fe854613bc1f99bc7e52a3d961de98cdb728b37032a0635f7e8383f69a5d2d619d19874027d88366249e7d91ade734d99dd1bb06618082b62576825cf8e97243e57a9ac26bcf0299c31ca13f64570cf08575feb5eaeae5e886f7d51ad1e3c6ffabfb6766c56747461aeeade98746b21a36cdec7d8e541933ac995b20cfe83f56fce5896b37a2c50b7162cbc640b9fa52f4942ebe63b492f16b68bffd2f50b7b1637e8f5e295eff3f09fb64900003deddf12116c2bcf80a73f42dfedf7d4d315b184117f5a5f6bcbdea3862050fdf9ce481a38b4191a3cf8d6ac64ca58ff5741e648de3f8180deaea5c0b4362fdda2427a38e6b04be5f237d652464c7c529abe91c5da1a185598e893787616098886a4f467ac648df64995d7f331219dd3198d9a0b2a875723afa88faff61b18cbcdb35be6090310c356b5c4b2db35b2a888717e0a29de8434e97bbcaec29e954bfaaa7d7645bdb40af0af0acc228f4f2c52e6179dd2ffd5352ba65a2121f3b488be9d8f41cd7d0fd6da9185593419b0a4777b71ad2c708f74666448f04daef60477d01d0bb82d1efa293d70f95097988dbb4adf9e7c9e39cb37f6d0c8748bf975684612a265b6906f3af2d72f702247b7910886c9a86d96fad7e5eeb41687939b86ca7bcfe022d4b2dee51068a3c85bd4680051531aaf84c736304298d753c5ebf80822336d40fac152e0867481400e6b894379c751640e4c46ddb45bb53f01b319589282480ee99085c2b8f7b98606f1c8c9bd49f48480f821e64fdcfc1cea8bddd7d9afda2f679be9e4ae70db054f7d2d4750a0abdc5f6f56f5c45571e11b91f8d8017780893fa5040eca8142ff569817ed02beec80b6f509112bc313578c325d3f2ceb7f54af5b8373dfea392f41d41d234cd47b9af5ecf60df709852be0ad08d6d16b50ff16c16534ed26fc8da4e6c78ed3aaed07ad9666686e9eeb9fe97ddad3342a9c75d5ab8099fed2bc4c6bf8a7855878ac0b2460182c8b8100083459e9198805e394726dc1894dfc4690a763f1a85fe34d15b8081ce2ea93f56236abe86a641022697473fdd5dd04bd7d8c9694924f533411d40162a8f7b6d3e65f1bb44369c48af5ce57adbfa1530c3b05b2fbcfc635e9970c4eb0608128b5209784023ba0a40a87882c90ced394c78db39fb6ab3ed83da4cd503d0d425f632abd24f35071210329391c8a094c551f53c51d6957f7dae266c7b4fb9e3d8e4f17dd0e6238f5977544394f116a21f00ee35a320fded778a62c3fd50bae65e9c4b502df4d725959f410ad918b8156ef42e168847b06208c05a61785e4629adc4d0129d48ddadd4bbb142774cdeafa2ec8b23368425620118f290c937b8b8140abc859af4b2638689ca00ac76eba0cb3bdf5f54bdd73a7d01620999539743330870c1f92d5e28f87f9583919fee65645fbe5d5e6be62564dd043e0647197090d98dc78714e23972be49b99ea4b30d9d22c9b29fffdd01eafcfe765bc6bea360379cb84d78140ac24f54d83c326a387eadd2e96c39c4ca2ace1b029dc586a731766df99671e1ccd2e08b5a4eb1ffb03610282f3f211a0684ab6cefca6a453f9079f67689d26d241791cb50b3eb7815312c39a5266457cbc3aed4fc08b8788d48c3f633cb0f2310830adb3adf03334836a07e1ffa463c3c0a498368181ea75b1c2fe3f04e1cb9f5d664ffee20b393bbb04df9b632847d4d3918930a4f97e7caef68b339ec163cc7954def509c8ac41e4c55728e850e9cb3115d25ac1c470ffe6ec70a199c0272207c7fe7bb6d3d0c1b3fc30f582263ba3da4df2e30c73e07d90540f343f00a88847b08d697e5257285b28da244b3b18b9678875f8a592878b1b1f635f26a746ad63c8cbde48a2f89965c2892131ebfa63fb6158721f5e041d3e1ab69759769e2dacac2b012af2d3ed0c67ac510a708f7d1b8b3a37274dfea2a35fa017b6cb82d70b86d9035acd76c7617fbb28a13c61e88ac7bd4d356e97d31840b7ee52baad98eef699f808983f5ee5a029f21e8463e33b1271ba3ce30c8403e0347fec959e2cdec88a9e96b6734499ca2e9ac5471840a8d26871657db53a38cacd1184122f1ce2a47af119b088551afd13a49d7199fe9527e430a098bea614ed23e238b71f4e1efe475d8e9c644b69ea070fc09764351621e34478e41b036154e0abb26b6e22754276939a8697f8823680e34be7f81e2d822ab27b06e48f1ce44fb9c24e0d503ab09a0f51dd513b9211d873db7218d3d06efbb395cc69f36379d4e0ade6b5fda30e9df425ef773e668f1a29a9692570b5cff5266d403d9f318bfc55c6b7d8728784f2a0e095b26a16f1a47c1c0cb747c5bc4ad903c3321011d2880ea8a36344d39e19e894cc430a720fa3067914708d4026ee0faa62c19ca67b0b8120652e04a8dd1e12cf3c540f25e98ccc3f4b235ebfbc06596c1ca8b2348b0021a495e8ab9dc8cb135c2c578688d98f62a5b685628f3845031dfe1cc6c969c475dd9c2203f2df5284b5b23e4e2403bd75302a4505e3fdbdbebfb73290a9dc527e4bf85969084d661a7acff03ef05c28bcee5dc4a27b812581ccfdd78d418aef699297f385ef8c74c61704b2393b39be18345cc9bcc8fabe77c4aec64f0ecbf7ed6503c8516c794e4a418849b3db6ddfb9a45048a6e0c9da9cab1386e1a69c299f90be48e17cb35b35051b58b6e7365ddf76eb1703f4980e30d2d069988683b8e1a53dc72b697303ea5c59d3c9704cb191d2bd8a8821318a17b80a8406d1c8c00423dcb6118aba3401e2a44666a6564bd4528e12d92b8aebfe96dc03e5e95754f630161b82c4c0beca298428e874a1b4f416c051bc9acff95ebd0403cc215f3cdf75fe049a46274c0559a4195a2c1407b0bf0334d310a03c258d1e16d5b2637cc978b5bf27d0c1f0d1370287bccf90b693f0b89b252ecd881d3a6521660b35c6124086172a8a4d99539ee867a5f1c93eeea98c3a427d1061a12a082e0d8c8f0a05ec059c82f8d077f9a9a2f344b566d028a8067db94a3ebbd596cf7dbfcb3c80b288a82b754506cadddbf62e43324b8e548c996ac66b5193237b83f17582c94d27aa774ef6f578623b84c8e717cd413bb251c9b4c6a3eff7c37f981c0ebe1b4881c4d668d92f42f992218505d9547e0d46050a30d03a5c07a3123fabcfbe5251c96828031da9e544c9fb7560bba7a49d0edfc7439557b11d07008221defb900fbeb52c296bb5a6ccb2048e34b95c0b4961ec344ff1628f9b1f0559bd461c5474eb990453f64dd998a2175255fc978048af52a421655ffaadfd24c05002d30c0619cd886416a4695fc337913584c94d6cabb2a5d6d89cb1a8193bd72452daedef8288c54481cda5a0bdd56db605aab2070ea20d75f2b87c1d54eb6260976ba560b6f763f59bb6c761f943c75a46f007461dd5c7ba3499aa7d9b21f65d4dd7985614eade4a9a1ef361b6fd67c0a8126f6f380588971ea72a7b64a395eedb34d0b38d6ad2feeb0f9a0f4ab57ceea30f29855771b287b1538e1fa2f764f9fdcfea99f4a5060728e2f434c05a785093028ca40728176f0840bca17020bd2cf975b734566c35286f84f0c4225530c47947f569fad9fff6bc59233d8aef2767955aa4570d290b8d5897e48dac6c8bf94d1eceff7b4ad9729f22e622b35d73118235ed36db9e0e8e1ad5641ad97200e399c6cbb4c6fe38bceaf539c4bf2c1641db766153d44e137fdf79254d1dbf956ae5602844566c9fffaf5bd3733605c232e70cdfcb9be342716600741faa998eab7cd62bd419a52c986482be6b98c5b9d53ab7f9c13cbcf83cf4ae454e14a567bd5682d1fa10736acefb56d9da21f6b9cdc9f668f1fc00e7460167e9dc73872146dd7e1757a6c2336584e6aa3e0bc2eed2a7a20cead3a89343679629dc614f1088e17a49cbdbaa3c19c5c5eddedbd1012589d77280a803ca8b236bf042cc47cf7f863e0876f01083e9423573247594d50d66a94df688992d3374da19edbfd942c894ab5a6371c0891f059b32038333e830a8cd3ce1617d2806b951de474f822d8a49f4db98a249904ab13d96d1546700e683e8767e530427f188f7fc4a910ee88efbc66d49cd2d23dc0d2207613d4c78ae11f7f8ce983874cfbc5e83bf624c51b2af9872e48054fa6f8e67a70b5b03bb14d37449a83978698af3bbc57f7aa5139933aa7ee196f036aed4a0a0d4625acc3f8a6906b46577ca6b712799b3757fd63fe2c2f0fa8226fdd5ada75ed0fd573a4dfab5bc28a5620ceb883b0e712a9eccc62fcf3cb533090303f62fb07acf691a930198dc3975433881fc977bec361b814c3b43753d722d32d9bfc53e4ad0f98fd93dbcd301d04f40609094740542f465791a8c9a7392d3c45120d212dc01421b6ff438ad80df408b776f2d99863456e3bf4fe4cdcc8c54a0262d7f46603131148cc92ee3613c73be9f6b06dce97f13a0e22286c8c6f2a68dd5aae253a53ddbe7970fc21f56419b1d19fab92ee0f5da317440e66b530821d5556cf9863e6bdfadd65734810affc3dd234e672d63a8442ce29360c0ccb6169b9d8ec1b123f0ca52fd07a62ec0f765337d4b86515edcc260b68b6c476116c185711abcbe6db588ce958d2a4debe47f0aaccc7ac423e5118a1148bcbb08142c74b899e89789d3c56c5e7fcce363a4720e7f1f8fc7a9fb751ecf3245c53aa78463c5472c5146cb39ff22315adfe6c855e8ac339e78194f90fcd1ec8b044d5250a9ca36d4f6e48dde1a11d78f0a962a516b9716054f0b88cfda090fa8e8d9e561c7b67b42664801566618a5c2ecd3d4515cb886a221b070262fc74b2ea981d77c7c06745801db275a25a17c0e00a022eb41bcc4e0fcba908833bdc109b530551dd0844c3fa7ece834206aee31ae352e6e4e6b46393452e892880bd2b5e0ceebc51aa69759ccfe2bf56dac4f153af69e7634ad47a3f37e355005f31f0b60366cab34c35f47bcbe7bec45581968994261cf61ec9506f283e4c3ca5f4676db430b2d651c6a7120d44ebb12af662dfc345c89048a2cc608b36d330776c3351efdb25765d37df0d727c6e30246a509e150c63df0cee019eec0a7ea137ee717fa6eba31234f101bec2864a27e0cb049c1b6182de80a6f05f4cc70cb2f6187d74efb4ff7b3ee71cdc21a780d8860362187b0f034507624e62ec34cc9743664c22b12ff5af2f39ef4a7f52c5574c7cd18ee96d304d7bc00d5e6404faffcabb1a9a41bb1aeb0193474da2db6ebccd84163adf1f5a5f761c92d1bc9b33da874a75133bdc03d6426d1579e1e43efeacf5564c0afdf8049daf703784f34655c12b596d2d5754a6d2b5ecd9361abc1d8de00aa9448b37dbbaf6e2a388d0a5b45b720f80fb16e86c9988a548df9129283bae8b93923dc0c2f521f15d86cddd692b14478befc14f7185fbaf138d034d1c08e750520c9339f20dc70b43c757dae9771b267607cb495d7df57d5aa3a4dd192192159126ef6acbb2225ccea82ec7461f9471ee11738cf99c8e09ddaea1a08fc3402ee0d8de4c6bd3f92dcd51198c71a15e47eeaf38ecedeb6c1d24995b0a2fb19c64fa7258ddd2cf24ed1ec9743481d2e59be83c4eb2bd6f24b3852d66a648adb6c8ea3a9645c118df3b14be2c843a03d95a1c96193a66771d717b8e21b895249a5c0fc41ed34d530d259ad7652567c9a9432cac34f32f2fec6ddf06f07120d4b5061438cee88c948e4c1b437a971c242d5eaba4af85373dc7fdf5492bccdf5f744cfa63cb91578d176c8e734ec4937beb8e098641f38e5acbfdb7f765db995f858d28e3eed4ce34ed90c97ea6564e7871142590ee694a19a0882a24996e25b6688825b506ebe7c8396c2f49d9c014ae662431e483a34b0a783eec90e62fac8fd289e068a91a9bf88323517f384ba1cdb85793dfc3f7c736eb31d6724cc382e945711f82ad6c07cbc5d37736ebe9ad6ea7743e736bb1fd9618657a515bd0d3414a297e5f59f60cc4959e659fb8b1d1fac143656e993d0c5329f7b3b52aa0e8236bac964e520cee597c12bc50f21885c3a17dfdda538564850906b7bca118a835d3bcd6fe3ba3dcbc1505ec36a22103ee73ba46c2c8441c1f303ae0bc3d21cb6e9d421b3c0819f0ffad2005176ba9a670431ef8cc932508fdd82487d3da2beb8e8ee4695ef986d86c062ba1a9e4272a34083a7bc8a41357b2488b97e9126ad9ed3f52c19355484f412b8f321551bdfd70626718cb112145d025ee24ad24e3e6a6145ce2ea64495d3ed5df83280655fe283664c06fe20d0ab4945837a273290b97a17b721607458a064a23efdd28e6379e7c057c9091490cedd56e8d3566ae4b6364c2fcf7d75264b1dbc20ca6fb8d04b64dfba61163a26b456fcf4b0db195e3beb5091aab03fe853a3b409d6d94bb9d4c7572cb151ab60908ae2cbf7770d3bf328847573d4b1e21916a4571540849570f620cd499643e04aeea813b627cc76a5a89c063858acb9c4e2dc341aeb072649579fc2f755bbd5f0a276a07735926d8ac0adb7a161a0639361cc958bdf67b0a5bb776e397d00facefbc56f2b381c1a20009e474699074dc0f3baba9d5197dc67012b02117dfdbe78a3f080ed1b69fe8b197be3ab22818bf72010bc6b5729fa98f56da24d73ecf86e1d71253cf776e11327242eb28d687cd8cd868f987a5e85dbfbe304352045f31e773fa2ea2c87d6929bba6b56d6929a305c1c25e16f3c4c97ebd9a3195958d85afa89ab26ce72c9a91d9bbaae26e1a3d77cc6123b5b74501d2905fccfe8b47a902cfa8d0c2468d73cc83cf1b0488a7b5980e83647a591097163879371c955b4bc991d66f32480ffd4ff918ec223dd3d28bf71ead65dbeeea0bce6d6b669bfb36defba37e58a00f96fa450d62c81a1a57179fd2a622d1bd7493a18049beca318b2011c613421c408d52ee7fa7e9cf043e356aca8dfbf29078f84b6a3e950fb1dd362142b5098d8488f0a3a499a2c1eeba5fd020dd77710f684f21db6e0919710e18b526431bd4f345a47be9d3114eb7717a461fa6ae9c23f851bef4bc6e312f24596910c85563a90977c3fd464c50bf159be94a502bdcab51f44fa4145760d0a8b87c33cf5d0812f8053cd6977fe60f29827b1be6fc69726f70fcd68cfea4746de447354aed25ab53f2030a794e672827e859a26e5b905805c04771327bd14aec67cb58a251a2cda736876c155209d7fbbd7a675422d1c65a93417ea3aa9881827df227cd3bb87f3c6fcd058fc0a00dfbe60813693008b1f3d343bd43cf5f550b22b7b6b80d941de1337c41d8ea5a810158836173a36c1738c2706c0c928b20019659ef1cc65e3c215b75d28f391bd3dbbc44496b69664dc722abd46dfd107ff7c391214402fe0c7ceb9e3679084b4ce09f10594b25278cbe9b8d302666cb99840cabdb9898859529e303d527ccd74acdf1c2237959225a3a8fa732fafd097608e110d62df7d1e6b7d8b0233b529cfa72c35b07820fdc1f7533fa6ca4858e5987d49ab8d71f0cf08e05ebd5712b92c102c7d84d08b5ca110a87f8603a04cddf84b756be0a78c677885c53bd32bc5f80e0d52e38b3b9805740a861a1a091b77d47f72525483d4205809ce075d022807bb5bee96aa7f9226999c4fde9495a0112eb39f8e621b248ce6a5855f5ca778afcc1264c39e7fa3e7a44dcbb3e8d96cace48e808969e7d6dfc2e780c1058d15a0b2d73369d3aed269573391b92acf1325c18e8dfec2ccb93fc8d8f3151fba975ef87dd753fe8ee123ced45a5186cfbf20e58f30fd8332a19a59fedf4a80cbad53171c4b55ed6982a43247418b417c95e4973755670cca4baced991485446baa0c76e5ff02d47d1f69ba8d8e178dacce3d6130198b6ba0d1dd055cb5512cf294db9557bd7068b33a6ea5b0d7f417e0ef4575c44349dfa1f4b4cbe9c89b1fe63a0e69970178b1d5c8d1bf846e00876aabdfaeb28ae1515cd42e763a06173e9ceae886aae3b21e9bc6ce29a558f0000a8de4f259fe30b768df3d06ea94b9700e0bfa07a10600e0ed6f5355bd567c5d53e2f01c3c2a8b94ad388fd49198c5709819b7bdeede93282e7a602c49b8b886d9fd00de3a9705c25148307ce76dc5ddfe4c6a44695ea59f0f53951318c7d5a441d5d03a75195445f42e5e5e23b2aa8cbcac545c624d1565e302fd2adaefe28d88e49a93351c7cfd90a5348786ad7c3c237d3d88137260e01f0edce12074f5952cb3a83bf34bbc898a9c823692e3793eb9adcbf7835cc98dca9f1046195f4a6132c85f43beb17928e16ca066f9271726b653257be996146865fbad9d8054566999f83e7e8543cf3f505b07702ef95a58d6070d1b0b04bf5e7f4f516b4bf6a2463f76c7774e9c405dfa449085c2d8998295e0cef89606108c2508c225669bafb170aee3538ee42a12afdd339a23fe95bd9f281aec47825d17f71175c8e835ee6103f6e668ac871cc6b11603e661888e402c4f8bf93298c377d1d1b06b814040502fcc848f6a938f21bba47aa1892cbb1908d5496fb6da7835f5ba164665b63a7f8529fc2eafd68ee978d69d5f71fedbca103b4979ac227247a0ae5329b3d8267000d15230ef7146751119ce8d63c2267e28598a829ae873f4418c031378a67885271d6d58b6f3720c0dab87d25a02647d5e892d0ab3f98827bf6b7689184e758e74dc84d9fadc3f56da61e9e2127b4f9906de75a1a9fc700b888c61d8dba793c70096fc0f706f51f0b23ec9397d59f11828206bbbb832544acf444399894cff2a3ac9860d06387729bb557b6c5906a07387f0057008d16e7188d1f8f55916fc31b958fae64fb86566886a15eeecdb994a2f6820a911e69e89a6b441a56e26d4fea4f6161c6fe96e7942e691dcca5b4fa425b59e13011ff15e1fb1759dbfb08a77297995d75bfb5803f934454ed856a7639e1e464b9e05edbd7c4474d0b2e2f8fdf76ccdb8b41f9f5bdfd9b6074993ae957d03e001da5436c816e01281973c43d41daa1b7b0f3dabcc9e7901b8016189e305e3ad8cc1adf1a532c4413ff9d248190a3ea4f1f6ccd6cfa255ee280c21752a377b8ec0000c4dac64fb6bd6355378ddc91402c193f44abee6a1056127e4a6dcd1861174aab488c949d67037f74f44492323f046ebeccbe8c20e17c77810a3279dc08ab76a39854e155da3a494c95ca427e4650eee387cb6a20d214d0a079e285b8932f6926e733059771334e6a720e756944ed58e0ae964fac68c17b789f0bca92fba4b6478ab8ee2028785de9dc6a57a88b2778841bae159961b51783eb6e2e1fd8e0551abc5307cd88d3d2ba67f4e6cd8bccfc5a6fe4f09d13ef653f583cce8adb148fc8770b3c68e93b289a8d1bd071de39d932e8c3e65498c3414a00b5965621543cc6bdb89509f95299246a1874c2d5f38d327094c08354532e86d0afe7ff1a63cf87c8afc72a8802203689d9b92a9cbca53a97f7601fbb70f404102a03dee1f072fe45c1910e21545cf1e3fbfe4f2edde8d00eb43e5b4560037bf3782fe05c616bd8abf280f67b319338cc1e38d316f8cd2ea8302b9037dd8abfa6386f6f3490d4a7b67e1d19adcb550eee40ae7ae8a8660203067f75dff62451570d4cb998d28dc5f70fc8396f901af5a339b0f24cdb6f28ab9fd41dc3da3fcc3955a476622288b62918a99114708f0125233863bb1345c57cb2b8574e3ee40dd8a3604fc2445b08efdce560022cd60b790dabf688a79dbb51fde50d7dd11b4e24fd06dd70cf31e9701ae2c187290c1b9cdecb42c50b1d06d275267e592ce2b8530682930de3f1881a1bd6c461c0009d897eae6775b99b6c33557989268e25f8a9793954a4e8c9df6fd671ac2c4e51daff186c858ca3b669e5d27e497146d9487b14f65e36bbb6a2a81d8c98eb6e6d4abf8eca554e043944aa714f86465f20798323a5e96624c6b2a522e70459b7cc2dc47ac05f313cdc75bf3ae970b5f8eb62e14325bf9991c16560147acf0a2dac5042a37e282ec1be8574a0f081555890366ae3d381bdb1c56506bfa599a3433fa3887637830421b207e2f29c8ba1e96ff80f713ca2a52fe8fad33d18bf75456a3ea7f630585071c7828da73edc5cde7f1b3ed707cdb44cf18824340e3ab8b5baddeaaa519178ca2b8519ec96a361909f4ad0b1d98d3eacd4ab24d2a63a411dc57fa19d7b9b6ad982b6af0b5c61695e7f4acb93013ef8f17b58f3f7ce68a4237829ce9b8f6d28b01ec5eb8838d84e178f2274046361c8e1727c5ccb62918dcb00ee9b8583d0548ab991f2eebfd4456a103ec80c1672da853c9b80cb09a9b6e065aeb779e2fc89fcf50d5c5b5a122ef602e47bb012cef7673e71c310dac00ee6564c76f5fcc33729dd3e02900be26517837c65e2d2c0985e21b5d693dc0cfa786b90be2cd1fea4baca934d06a50b3d033d1f487e485bbcc66505f23974298e98d9715a249e2c576b4aa3ffde4a4755ab9ee67cec94ac3e0d801a35bbd0c33f15abe3a4dee16ab274c4e05d20ff17980246bb8266f3fe7d41035026ba4a444ea89fa95927a6f35a4a916a56f86eb8f2f9acc46177c93ed48472b1b6b4120cf17f92fb4920fc6a81912381c20df8cc908726a83f241c14c4df5339d6fa185c564ff3d39f4951bb778a83f5cc509d18a0e8250e7f9e37b6315390cac852933b5a73c43ced5d2f2509f53c5a3ed13ba6ba7b6238399090739e3a0c646426f3db4b51672b34e57e90afbfc4c8f2aad767d7c2c422e1bde7f9df01c3deb27f697983b9e48d51b3f2cc2385c2a7019a78c2b36f9e7978c6dcdaa1debda0486e3690f3cafd3ba40b169bd471e9ec3df4db342289ad6c3c9f5652568968deb1d64bff5a4d534e9cc5d699ead64b5602cb5895fb430233273a9ff1972e7cbb254d4fd1dc84b70d4b318f99b0029bb09dbe9dbaa10b78e83c817b9cbd984a1b6ce00c21b85330fce2c53cb0a821ce094c707a77068df4db7ec0837bda5adbcc5f641da617780b83011ebae44e652319f43c2f2c0afffbee4e5079348aeedba0aee1b6baa42f194ced0398c3621a0722a9722419c8b72a0e512cf8ff03ceffc7587889c3fc47d1cdc201a5784f26ecc1c27a83f8efa2bd4701cbb60a2c37c60b7dca8e0a51dd0c0da81e0e947997ddf8698deba8dc4bf95885bc26d942e7a41583b5b2af9d8fe04639d329a9ef84a01ab53b10cf573abb611415a47551875ad5ce6e3f61faee57c9fcc4ba81e1ada7a904e3234251aa531d46cc20deb638e288882876a600bdc2d265dbcbcd9d4f1affa3dd29348cb2352287843229899130d73f0336f5484ff12e2fde9eb842cd5bc48f108d36e9c68c4963b6e2694c2832794731b35fb06f0d0d4f6949c226356b81a60b5939c6958f40e0105dc6fb6d602737d472eb157e1cc3b0c067cbc82abda99a9961bd6d247480756cd20f937cb54306302c7e5518f1df401341210f2f6e2e09814ba5e69d7c701f0812824a1e26124880623c324dcda0d19173e8c1cb72fc89f651a67394a101280d57f3e1393e76a8b4f8dbcb9f6c65fdb5faa5486aadf9ef3107d868b2a5e2c3ee924b742d0a90b66d1149bd888ec4b5904dbfb575d6013ce7b8a1159603f2865f4c1db753b7056822542268f313ff7022f8b71903958a205f5408146f133525c12ec890f5832b080f3154a0cd4eaba7bf17c23251c933b67b23a26fd3458056852725995e62a992c5e34fdaf08f5b586dc6ff411a5e5db35f6ba76ebf3624c12bf8694ac92a4bd9820ed706c6a0cbf2b36ad63bfcf8d17dc3801838a47ce8ae9b3ebdb5d91aa6671837576446d006254b9a0e0bab9d3df1985bfd7965abf51a242e72b2499c5037cd5ba99cb434efbb0db6078bc46475b9317e3f202db5dc1d2e2474fbc959ba36bb639c6b80c34354d4e094ff4eeaa17dfac3238ef33aa3fe71f316228e03714c3abe31add2d6a0ba2c8fc6971e9e83614a433f5520672e6af45a386d8679ed3686f841acbcda47b0f2a0fed224b33e4b120e606123ef7f303657f032b17bc7e7212d0bb5e0aa3e17cc83afcafdda7ecfa284932d82499867282142ee56bf27b18cba46df5c025e2752cd1effcc15191ef525c8311c03bbcd8d731308f4cd9807419a77fef80eaca909c801695929c3f8e99b1ab480f47b721fcd444b76960d95900a7e0e4707259c614d80c4869b7cd48b18357ac8c8b0d9afb9b2b1994044ba14f8c47ce4285d5531650801a21c80e248c38b6cb72524b3a8fd9baf859b1482d2074daaa6642a67a245c7fd48bc318456c26c8209e0ac78107802e937125dd994c1c119979b15f6b83ccba2d1662220ae76a4209599404c67063360649431ff2c1d554566f338559ad43088c413ad170814dc6e30652ffd1a6e5328869fb5a49407efca9cdce008c857017743d5b3b11f29b39be5eafaa0327c442ce05705d7be2463c3394392d898543b98756ae5009808b9639fd9eda7324ffd1d1b7b187af9bef51feb7d1f7c11db92d2bcc28bc80d759cf76ea46fe5e0d5f500fc7914f853c6cd8401defb55ba401c9fb4706120f0879ed4dfb1c2de9152d367f17b99529e0ae7e64eae2b56186dc0acaf693bac9dbba53e7adb130349a99f5bf7473108d29e907d12cbabf1458e769fea263ade33a5960d65517f1eac1265916f0be26a05725d9b7b87f5e9f707a4ef4136fc701bb279ca9a9ebf4bfd33b2debd727cdd66d9e972def3e5b61cb2e5cde12bba0547e990d249e621cf4f865f83f0d0f5836b1833eab59099734113c57f439435c3036aec4d29a07dbe1699d55ec5a370e37b994272c4e32c52e0fc0727335276c8e66db41a57a5947ef98aa91314c7141488dc181da80170d4d81be4cc6ea1e321bf754012459bcecec6003b4a306c961b8edd1aef52dcdeab9766bc0de7d8490df25f664d0b964c0d67bfd34f321825ba2129f6c9527d46391293b1d219beec5e42df4025f763887b74945b90715e474071d5b490891154cd790ac74ebf0b55415c3f8660b51d14c7c936b0ca47851109678cf953416ed97ea56c92e6ac9fc8f9c12a94667a2381d1f6046a40a72bbae27386d37b06263ac7e6e6f781e2960ed29ad7b3949ff026006767e03a31206781735c44735e2ae23cf3b108c6db462f580cf3abacaeda3bc4212b529287c9a30346b958e7c198df7f3abb05155168679e26e2206ceea282e7c856bf842ce18d83731602feb2cd5b1ccad08bbe8d9c616498498d92a7fba288949d6e7fe9fda94401199500aab609509eaa27eff08b360338ea665d9b6f5e7e3d1e823f45239cba01b880f1c307caefd8858f59e8630d1bd49d0b6bb13d2519c43ef74a5f3576ad609e08aff037ee1bed02e3211138e71659d75bb8239fc24fe86808c37479831e849fb99a66ad13734ec574f1992e675aa5a88aaf0f92be09da0170845804b872bb2b81386798ba804d63f7a542fe8950543b85862e02bef4efe4caa2589c16f1fbe866098babeb2c30bbcf628f607f57495060ac4c0d121853464013e56bdd1bf5810632f5bf28c3e059fb2015ea1de139be188c39c7d2bdb91ed8add3ddcafae88ee8d7b4a6553d89c9b22c7fb36ec413a918bc01ec32c5e69b2a9e373740d95b76ea0433f4cf0ce8a8db65a1ba7adc7cf962925dd14328cbb5c41266c7a9f273bb09c4039c2220349570b4fce5ebf8448d77a4a4713e1b8edc8c10b661425e62fa2904c0920b56730f23d1d49b9b9b614353acb7f276968cee16b3dec2b9ddc2162fad9b0a52bee2b102a6923a1629c348ee99fc611b29921d4eee07fc45ca643c87a6fe85c04d26e0589013f4a78a0eff4fc95876a84a22ea72819ef6fc966e80f465a4e0953ec3a941b881686f30f44b7184c532966a3a4e97f4d216d2c06b4f74737f1ef796a3e071a1baf2694ec9ef9998eb33d7824d47f70a9e5250368a29cb765dfb33a6383d4bbf310fd310249436f8f5e1c55bad08a5e6480952c6ac51003c63cc85061b0512a379e94be8dd0b959ede69eb6eba00b071282abfe5f8ccf6db9a611633aff93ac5b457cc6cbe14b5e62c9828485da850e98e5541f958be1ea2cde772b04f36f554a7bc1b4624c39734fd10f8381b5de37680afb2a259e39d08f2acd5219bb8fd3bfdfe3a8ef193693d64179a8a63fa68b6a48eae91b99f971f4ff8a3a57ccf676a616f237679075e3b6b70f39204dfb31cd8ada5dda415701d3ad6fa9d3c9530ea6d4b2d6b60c4403c6a65cc72d98effafdc57ed8fd9d33c952d3fab41000de14857eec3fb0d60843480432c582c6f9a5aebbfe46e91a562ae400b8ab5f6c453611798271282b915a8838c454f2a6901c73d61ced27c06e0c6fbe0aa2e8cbc82741fde4b0e462a8aa6c8c203c79b6be49b895b696b2de93823eac3e00a10d5025c870efaf07264a2219f5ef05a5f6cb371a843b66f6cd9ea8e2902eba8ece475c75f4d888dff384c04aab2d9eccc9aea2e948aeb7688397b3f288c8bd39157ae372eb5a8e76b56581b01b2fa40ef62f4b93e59bc8b532df5cb829bae3c655bf1176f182be48b0f2b19ad1abc9e11e189124488ebcde393c05cb672d60d80198c545188dc07b8131e643159a69a9447c7d611fbb2f3a3456e5f6155bfe838b536e636d29094af44262e5869ec40566237729d6017cf05c238362bcc59b0f2e4627d1988a900ce1df8ea229990e98004be9a333b57d7f1ff314a4b3f27d04f89f80a7418d5c7201b86892cd7a7c850fdca0881e62d283fee99baa997e69e79e6a0777a231acd51cd0dfe697c2ef668195eed2bc102aa5059bede87eb5050837c88375aac0294ba3cc5f71ebc1017b3c77e005e31b17afcc4aad9e5859e7d17541fd012074dea191cd0adf57e1362f790905010a41a6bd3ac6b326cda5dfa59d11681d86410dc2f1294816d95509f1c181b7a7a1846950d6f9bfefe31abe2856cba479e181617fcd1c658e93e2498ea61ca693fc251cbeb65611c14524dac273d6db46a7362296345f1ba211ecb61995c09b306e27f0c5e366e4ea673998fa31e0e59d03779d32eb2fb3ee85b0234899df44f39fdebef83fbf3b5e2150f4c4354e5d91dbe47fdacac146382c9ebf605f07fd7d2cfa74df671c3b290350295cff60d030b60d2bb42aae7606cc761d775996dc09a7f0ef454cb0e300a541124182628f25cb75f22031bb314074e737881d0b1c296d226e68c251fe9aa15cff00d1063507fd7e0426acffa45082655130db093c39e4552f7a7f860322e7f275582d98edf1b1937f06c054f7fe6f1e64b392595803b671ed38a84d16722ffc89c9e7d6601514d1dc678e8a8f64a1a8f808cd539f10a0e2025737175cd8eaf5580c4eeb4e388b48271b1754c7453d03b03873bb337f83b9016aff366b4a1d56848bb22db76f1af60469fa07aa004322d2212184b856041ffcb9ba8a958f7e4dfe458cad4a5b6d15217925b5afd2fb64083739481da55d603a283a87eccb310499267300be707e4471afd8c799a70dbfa7798de7f6b3d3490bdee0e3b18872aea1648e0f9df08bf560259769a6d5f94a6a4a7f76b7cf3af742ed988dee89208d810f837f84936bc8d95b591e0e47aedb86720519360ab4b403089492895dea74e01083a40c68c8915cdc3abd307d721f8d2cb3f990f68ff13a22966fe4493af7c52c3a4317fef9a5925677901082c78fdb2ba7f1247b7a0c05be7982301dc4916f7841d5b5b79b87f889ccce10729602e34be975a6abb8ddb4a70c9f837c00deca16b41e61889a7a6aa42e73a1a08a61da6b09792b8a66f20827af0541439968404db6a4b8d866e894633b53e05c23fd9daef809af69dd778cf78ed7b438b3f481cc658583e80992cba8e102d1ae390f14a3126c243b662b5e4999d13237d2f4c78826c0e56a271d2ce6b9431fc14afb8cf3b2683d6b028ce4b7361788e06902797117ec8dc3777d38a69385104622c605c9dfc67b74c940ca9a1d6b7d3ec59cce4fca83f7637d5a87578881d6819761306033788de40a29ee23c4b2ad0fa01860367f47cf44850f3fb5d88aee388205f0ead376caa3acdb641b0684559bb57209a1f92a482abee92088b7f2b6a02e4b2201e8cfa0e65e8a9258a141fe7e894f13acacdfb3b33611b4758ee65077e42f286bd8d0bdc024c4ce2ced2eda639225009b45cd23a0dfa8db88f7c2a77463ad9794c4a16c0e7a4f34f2b5d872540ffcbc1f6cb9ec69ee589dac8e8e54c73d670c0913303beb3a8c43f19c871ee5916aab25536d8d7299a7b5ba5b3dffbbab47d235d67e244b12940a0138099a5f7553fa07105b422c263b8961dd4dcfad1e29e3f3b232b9db9b8f52937656d5043ad0e0ac5cdb95157ab092e8c7c74c4cc92a4a66e953b06b6172294d3e57c662328423d9e106a4eae6f381ac26316eaa8f60bb62a624bfe76207c5bf81ec8136f712d73c3741bf7d6921ab9dd0d44b2cdd30ba8d871e22c2bc0044bd623b96cdf6f6b07bcdbfe91485d971bb9c1e03450a3046f9df1458b81ceef8042d94ffbaeaf1e6b5eb95a6d2113b7b8beeb4387aaa96a241256fd0e440b750fc6b1564c8bad6d81596ffd8204070a2f47d35606aaa499a359c34ab8de5c281d076380b8842f2b0ce98118f90eccadaf76172b3d6594517cba56c86b04472823a08ec554aff1b43e361d1c3fcd24b6511dde95df79e999ca2ab4d35457b929d61b9e1ccb378df7af16b9623537429454d2bb5a1b2494d5fbe0e7481b757c8275ee722e0cc40ae81a981742f855328b5b6927d01d0062befa9e8483c26bf619fc4cd54978935e1b2b7fc83424490c78df6fa7420b107165a3913f1b5f3d0468e38471cae06cfc506254837e9b6804b2fb7d291007217381993928e19923c11c87125592c88e245e2214501ea75475d66420c71fe396799b2a519a15831a6d1881ebf9b1c5b79b121a80856bc7c0f696de99578123660cc78805f5076adba14ae8810786e445bfbe14bb783417395d14fec94826f27fda0f5f6fe40f8bc4b71110b0adb63389c88d0655c396ab938727856b56b01c1e3dc382d2c0d32f1b9753d8fa67b910bcb098e450caa80e28ac89e4955e7b5f2be7fef1af5e6d9d00dd17d269b9444ab5dc1d39c1fd2034b9bc0e4cbf9447569e774e3c309e2b255919faef07b960ede3accbc4bbd20f213f7436e3456dea268930677795be77ff2cc262b789632804a19ce0856df06271282854ebe3331f2991e5190766ccd8e37e35b3eee6525433532ddb3ae6c31c0a5bec591253cd3a5f3a79481163347587b74cd2ca61c899480ba702423b1019acec6af5126863e54af3848ab21980cb2fdc1de677c4402c41693acdc08dfbef6b5fbae0d494c260c7797b27947215a87ddf11a39ef91cf341a68aaffba69856af3196f75614ab2c0c645e8b18001985b9af0fae96ad92fb520892a6b31133038bbb8225cc1a5bff68f704de766ddbd315b61cd7a66006cdb6b99a116f3df3be01d842391100e6c41a42ed126a7c55b35128b20476d1acd2c2a2891a3b266106d9b3541bb7818123af5ca0b79ee490c3cc9cef9a8e8c43f2141f563d8336924898e")));

        byte[] opened = cryptoSignOpen(signed, pk);
        System.out.println(Arrays.equals(opened, m));
    }

    public static byte[] hexToBytes(String hexString){
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        return adapter.unmarshal(hexString);
    }
}
