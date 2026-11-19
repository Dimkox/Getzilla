"""Conservative recognition of six complete standard license texts.

These fingerprints qualify a narrow text format; they do not authenticate a
publisher or decide legal compatibility. Full terms (including disclaimers)
must match. Only whitespace/case, BSD list markers and introductory title/copyright
lines vary. Unknown variants and additional terms require human review.

Reference texts: https://github.com/spdx/license-list-data/tree/main/text
Retained source hashes and positive fixtures live in
tests/fixtures/security-license-texts.json. Updating this table needs review.
Complete observed file variants are qualified by exact UTF-8 bytes only;
their full attribution, terms and artifact provenance are retained in
tests/fixtures/security-license-observed-variants.json.
Six further exact complete files and four ancillary files are retained in the
security-license-frontier fixtures. Ancillary matches grant no full-term credit;
the consumer must bind their expression and independently verify every named
sibling's exact bytes and complete terms.
The finite NPM complete-file table, source attribution and review-required gaps
are retained in tests/fixtures/security-license-npm-complete-files.json.
Its README container entry matches only that entire reviewed file.
Exact multi-grant bundles and two complete ownerless MIT files are retained in
tests/fixtures/security-license-npm-bundles.json. Identification does not
authenticate a publisher or supply missing copyright attribution.
Complete Go module/toolchain variants and multi-grant source containers are
retained in tests/fixtures/security-license-go-complete-files.json. Nested/test
source terms identify text only; they do not establish runtime membership.
Four complete decoded Protocol Buffers BSD3 blocks and exact source-container
bindings are retained in tests/fixtures/security-license-protobuf-bsd-files.json.
The source reader owns decoding; this helper matches only complete UTF8 bytes.
"""
from __future__ import annotations

import hashlib
import re

_TERMS = {
    '56959050891f7b737ac4e803051170c7197f02df73d80bd9a78d968e305bf558': 'MIT',
    '948703bcf1cb4a2dafd21676dd01e40a58fe21bd9b425c000b9070eccb441092': 'Apache-2.0',
    '11cf92b65eda2f9cd73e18d3066283da5c37dd1f10edf0e3ac9889ac7634fe65': 'BSD-2-Clause',
    'f7737e83d7d22d6fcf82026dec12bd6d8a182362b207e402117edff1f58bcad4': 'BSD-3-Clause',
    'a2a686418bbdbf37f28aaf01ff3aef45cfe077a641470465923c8c23fcbe08f9': 'ISC',
    '08e6cbaeaf49ec3bb90e15e4f5a18c018eae23c7a1431f60f6a2f32306cdb707': '0BSD',
}
_TITLES = {'mit license', 'the mit license (mit)', 'isc license', 'bsd 2-clause license',
           'bsd 3-clause license', 'bsd zero clause license', 'zero-clause bsd', '0bsd'}
_REVIEWED_FILES = {
    '37db5bb85926db28a427a25867f10b1232003aea1be69ccb851138adb8e6f361': 'MIT',
    'a97ac230e5f33ef10a5367a850eb01f91f1a0b064e34742c7794d2294557f524': 'BSD-3-Clause',
    '804b59b25f2c31bd278f9202a19ae49a3945aa2664387e2d0a128c7cacc61ec3': 'MIT',
    'efe1acf3e62fb99c288b0ec73e5a773b7268ef4320fe757ea994214e4b63c371': 'BSD-3-Clause',
    '09e8a9bcec8067104652c168685ab0931e7868f9c8284b66f5ae6edae5f1130b': 'Apache-2.0',
    '0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594': 'Apache-2.0',
    'aac73b3148f6d1d7111dbca32099f68d26c644c6813ae1e4f05f6579aa2663fe': 'Apache-2.0',
    '602c4c7482de6479dd2e9793cda275e5e63d773dacd1eca689232ab7008fb4fb': 'BSD-3-Clause',
    '0a9e78156ae8b96caf1b4f11ac2df424b83de29736f9e757630548a6272fdf90': 'BSD-3-Clause',
    '835586ae156766a24e3c103fbc55d9af6b1a16df57ca932c97482a2737fd83d5': 'MIT',
    'a338a09e00418402e779e3ff372a2bca3be66259d6192e0a9fe2949969d648f3': 'MIT',
    '4ec3d4c66cd87f5c8d8ad911b10f99bf27cb00cdfcff82621956e379186b016b': 'ISC',
    '304e4a73f6212adaf242c78fcbe1dfcebd78d8bab53b007fe69b39fc968292b7': 'MIT',
    '511ea01f49c4e15572d1a0dbef3c10f3e26425be79df7ef599c3b65f9bf55281': 'MIT',
    '1a66adbb5a45806b7fe0b5ff3e78008b57e660f30e688286c0f16a6991f10fd1': 'MIT',
    '8cd41c03a45ebf957a00d335d9dfab638b7ddba797a7d2f23bc1c4157a50db72': 'MIT',
    'ea5a8caa168f387ef2ccac8d7eea12d3be7e2e70a8b7125b68dbc8d1e7fa1998': 'Apache-2.0',
    '257aed98914108e91a337912727b6a802eef218248507f74b76faffaff517a38': 'MIT',
    'a6db8096b2707bc0102d256917d4d33f298ba36d8c3f25de067a2b5bb379db27': 'MIT',
    'b9b3eeac9f4ae8ae50773f318ac29f2052bbf08ee33fb6bb024d90d86c7492d2': 'ISC',
    'da16ddb65f8ca390998fb99223d0112498b56b45784d00afd77ff8ce1ac4de8b': '0BSD',
    '210b19e543130388c68654b7497e967119ce17145f66ab7d85688fbd70f08751': '0BSD',
    'd06b5d27bbbbe22c36b1fd88406b1208876e2d37d795f5b8eaed951a459a3111': 'MIT',
    '5c932d88256b4ab958f64a856fa48e8bd1f55bc1d96b8149c65689e0c61789d3': 'MIT',
    '91fd2d025ca697f02becd68acaabc6373fa853a04c4f7543b306e830d3ed6b36': 'MIT',
    '5e3400b93bbb099e83e52bab885e7441750673c21f97988ca3f1240639b63283': 'Apache-2.0',
    'a7d00bfd54525bc694b6e32f64c7ebcf5e6b7ae3657be5cc12767bce74654a47': 'Apache-2.0',
    'dea9265341829002e2c23a7372393eb2ed6e26085fb623f38a4ba0af833f30a6': 'MIT',
    'c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383': 'MIT',
    '48da2f39e100d4085767e94966b43f4fa95ff6a0698fba57ed460914e35f94a0': 'MIT',
    'cdbc258d13806538e727964c2436a8806e6e2496ccd616224aace6f7bf98dbc1': 'ISC',
    'a1bd5deadb6a06dd74efa852c1b8b23f63b67f2214fbe9c8bd591da51da69268': 'MIT',
    '68f12f6e2c33688699249c01d8f9623c534da20aa71989c57b061b7bc1676d14': 'MIT',
    '06bafa45fdad2579ba0e43b0c9b2c6290287c99c4203c300254a462b38a307f6': 'MIT',
    'ddc9158fa20e427bc12fa8e1e6d07c642ed4d2c618607df768b30ae2986b3b7c': 'MIT',
    '47eb8ca82c798246774946d1be0f9aa08f025fa8325ced0947aeeb4c05fe5547': 'MIT',
    '33b734d60042d0fe0c92dd1fc1e874193a1c899ec3e276a2eb935d2d0bf5b710': 'MIT',
    'c542ba7851b5d39a5face477e47a27cb7c00a9759e321b66824e79718bffe1ac': 'Apache-2.0',
    'aaa78451b6fecd1b9c4594c796c133c0e90cad100372ff8bc6de615e9ef9adf1': 'MIT',
    'bfa751427053e9f0e4f2af1e62862681cdd45000db8d8db753baf7d462cb1a08': 'ISC',
    '483acb265f182907d1caf6cff9c16c96f31325ed23792832cc5d8b12d5f88c8a': 'MIT',
    '631987b7616a325a5b97566c232418481ddf7dbb5ecadefb991e791876cc2599': 'MIT',
    '93f5d82a8d59442fe3275383453a255fef761647fb28265644010ba799806148': 'ISC',
    'b173e19b9a78df305577ace0e52ef45a4bcc915ea28b47b256dc3b68dcb1f7e7': 'ISC',
    'f65c5d9f22a317b2a10803bd1868461ce6499c2ed7217bc80c0cc772a748789c': 'ISC',
    '5ffe28e7ade7d8f10d85d5337a73fd793dac5c462fb9a28fbf8c5046c7fbca3b': 'ISC',
    '2144eb6894cb440fde6b2b3aaae3b617c8f1dc9bb19813079dcf62ec6c517042': 'MIT',
    'c7cc929b57080f4b9d0c6cf57669f0463fc5b39906344dfc8d3bc43426b30eac': 'MIT',
    'cc1dfd4dafa27271e8212cd3b274eeb3f262e40a6fdab36ddc3f9696f706f58b': 'MIT',
    '71f83c4c0621102a56d9853812777b85751bce7e9726f686f5b056c1f8a4b0e6': 'MIT',
    'd11323827fa4edeaafc437cc5b91b6971b335f0127efeeb42bf5122fe8657e8f': 'ISC',
    '833faa18ac4b83a6372c05b3643d0d44ecd27d6627b8cd19b0f48fe74260cf39': 'ISC',
    '05991c2e8f070b69ec5b656c2c12fd07cd0153dd157d39b050b82af59b319a01': 'MIT',
    '451ec07eeb9c4e1b86de9abdaa426462a8be48f887ec7421cf0bbb9c769555ab': 'ISC',
    '59a400d04c5078579acc27ddd6452c1bdf763f9506e01364700935fbb1a7c91b': 'MIT',
    'ecdccbcf39024f624ded480c01c0b25458e1eca8f26ecf040933865ce56d9a4f': 'MIT',
    '8cd23e2d76d2791765f7dd1025a9df99d81db91da9e2701f283987a1c0435aa3': 'Apache-2.0',
    '69dee148a2cc470554dfa7142e830662062394d0fe67cddd379aba90dc60d6b3': 'MIT',
    '309dff61c243e706fac25101a9bdb585f7e2db45e32915b08cf47518d2075863': 'MIT',
    'b7ad8777cf2eaca832498a2bd34fca0a5bde02d74158fa6c24ab4596d4f73a25': 'ISC',
    '0154425673db15cdfa80ecba2c9b1f1a867f7197a006764712849bfc3a93cbb7': 'MIT',
    'a889cc4dbee2ae172c179856b25d75b0b7a5a136e1b97109b9b590b2ff1a879c': 'BSD-2-Clause',
    '6b7a1792144374d84dc5ed3655b8bbe2754d06f4f1f64a9fb8b9de2d6f448b85': 'MIT',
    '693866fc419c6f61c8570438ec00659d156ec2b4d4a4d04091711f5f11a365d4': 'MIT',
    '7c77a44a8acd9b41fdc209864a8016b3d430b5d0e09309818d5b7444336df744': 'MIT',
    'd408f38ffa3355c5faec517153295338892eb0f1ea43f57874bb23c6075979b5': 'MIT',
    '9c63a23124d68cd30cd316a94a1a0bca34f032786df6df69fc4b5f136bac8d2e': 'MIT',
    '3a61c6c96caf5c1d9b623fb9b04c822b783dfcb78aa7e49c76a3f643e6ed7f95': 'MIT',
    'd49ce1d45d3503ffb27bcec6f8b15499065cb306553b3f1db39611f200e6f471': 'MIT',
    'fa5659948374d4f555594f47f6da073b40dc503e921aeeece30df4362b3051a5': 'BSD-3-Clause',
    'd4dc58571be1260e45f2fb8ab174e0a838c9ca361720e1b0e2ca020c037988b2': 'ISC',
    '0cec06e0e55fbc3dc5cee4fca9b607f66cb8f4e4dbcf3b3c013594dd156732e9': 'Apache-2.0',
    'b70e7e9b742f1cc6f948b34c16aa39ffece94196364bc88ff0d2180f0028fac5': 'BSD-2-Clause',
    'ff138e683771b187f3629c383db72ee7d632009010a36d08e18e8d2a34222ec7': 'MIT',
    '435a6722c786b0a56fbe7387028f1d9d3f3a2d0fb615bb8fee118727c3f59b7b': 'MIT',
    '75486ea0af9309140ca6e2c401d7e67bea8f4892344e5707f6394dc5e83dfc44': 'MIT',
    '14a34c4db2d21bf9cf80d028b802cd22fed9bf597a6c2db7ce30ee6ffd04967a': 'BSD-3-Clause',
    'cb7684632b729955293cab8a0bbf4134d53d9532a30761c33c8a4878302a7bd3': 'BSD-3-Clause',
    '646f8936b8ddcd14e13e578ff6857e368780b0d1a4f6066bee89211923a373e2': 'MIT',
    'a096a435e19bb6b631da46992c011a39be563e97ce7366879ad516c772904632': 'MIT',
    '9906940f61b1f0b533fa7d99baf55178b2808fbe113ea51dfbfad8572ccd5f2b': 'MIT',
    '8d774b8e55770e19ccdbebe68a10c7505efaa6988257e87bfc58bf0c6675817b': 'Apache-2.0',
    '80ca1b3a01995790e45d075bc37e190597e317ca637e393ab742159cdc0ab9fd': 'BSD-3-Clause',
    '11ac92da622d8d25df663d4bc5d12f464da1a98a9fbb75930e0e65cc58b80a2f': 'MIT',
    '2252a5b1e2b1d3663b53ea77051b8ed065cb9270a3d1174d5d6ead8a2de051b6': 'Apache-2.0',
    '9a6c3aa72d265f8f5fd6068d3de786741acb89edccf1c4011bc6a8b2ca64668c': 'MIT',
    '2d36597f7117c38b006835ae7f537487207d8ec407aa9d9980794b2030cbc067': 'BSD-3-Clause',
    'f5122de47ce62d57dcd3e57cdf778ceacc3a847645de3332fea58903def93ecb': 'BSD-3-Clause',
    'c3880f30146c2ad11c85a243858027e8a1d61e241e53284d7cef3aa9452f16df': 'MIT',
    '895d625d7bae6d50064367de0c9f283fbd4565da9cdeb103620fe357d80d52a1': 'MIT',
    'cc4d4de0920b0d3912203b5d9aa76728ac4a11087f55da9ea00576db7d1e34e2': 'Apache-2.0',
    '398c0ea1c3ac6ae548f77b1f5c9217b2fe717de3ea19a57e025fb2f686b91025': 'BSD-3-Clause',
    'b989f3bb73d2e033aa1bf21c5d95818009719e770a506421112e2836fa9e1a14': 'BSD-3-Clause',
    '4bbe3b885e8cd1907ab4cf9a41e862e74e24b5422297a4f2fe524e6a30ada2b4': 'Apache-2.0',
    '26be8a79415737dfe8edf1be62e71afeb8c770ed5a5605a06270d5701830f47c': 'BSD-3-Clause',
    '1b93a317849ee09d3d7e4f1d20c2b78ddb230b4becb12d7c224c927b9d470251': 'ISC',
    'cb5e8e7e5f4a3988e1063c142c60dc2df75605f4c46515e776e3aca6df976e14': 'Apache-2.0',
    '9be5d04bb4d706914d5bf943710da4afeb42048f7c529902fb57c82762a991a9': 'MIT',
    'ba3065d2f4b11bb42a0f7b708b021d1c28fa45d097b3eab3e7db9ab4745040d1': 'Apache-2.0',
    '2d81ea060825006fc8f3fe28aa5dc0ffeb80faf325b612c955229157b8c10dc0': 'Apache-2.0',
    'ce63850f77649f00d1394045e2794ffb09a5596beabac51c9548edd958845d7c': 'BSD-3-Clause',
    'a973b4498c13eb74baa2a8e5c351426a6826f2fcdd909916dbe53ee2e755fd71': 'MIT',
    '3232046a5fce355338637b40a95c60e029e23b281421d0809570d9c8ab7b098f': 'Apache-2.0',
    '9e09d454c08e049297536ef33801bd13590f39d91beb7ec86fbf30aa529706a7': 'BSD-3-Clause',
    '9cb8ce7ebecf456a156e04c999c32b2eeafb3f7d7e05b9435ac8829d6e0bf734': 'BSD-3-Clause',
    'b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1': 'Apache-2.0',
    '2dfbe6d2b5eb18b55148f3805d88648a09e0d17e38428123259afb08c8996e37': 'BSD-3-Clause',
    '78cad457d5ea7318230f3d969d4cdf29cef45524a1fc8ca3a97646da1ad7a841': 'MIT',
    '4c1b2259f160d975ec6594b602be5db4e6c0c06afe312ca3cd7cff91b75c7c26': 'MIT',
    '050855d9ceedf916a9e9f30d20c6f61a484448d2c2ed5810934bc8aef43861b4': 'BSD-3-Clause',
    '4d324e3ccdba05b20e3ed1b9547f70f10da14e095ea2af32a895e8858b28a396': 'Apache-2.0',
    'b28a26d78f83b190c509c24ceba6d374837ea7263bbb8285b48986821ec7ed9a': 'MIT',
    'fecc274e9b67f7e128c7d2ba1ad68fcf23b18fe0448d3c3671e943763502d504': 'Apache-2.0',
    'dd26a7abddd02e2d0aba97805b31f248ef7835d9e10da289b22e3b8ab78b324d': 'BSD-3-Clause',
    '8d63e48c7cfe5037ec918e8f0c6d0c00248807c095ef6aabe84535eebaf0ccbc': 'Apache-2.0',
    '12641e5dfd397ae2acdd28dbda45f8e559afd721d5a223f3ad820ca07affd777': 'MIT',
    '5a93d5831e1297ab10fe643e1a631e83be392896da14ee2951285a79012df69d': 'BSD-3-Clause',
    'd9f773a3d8d9e023744b73a755efe6c83c7ddc36e181198c7711cbdd6a7633c2': 'MIT',
    '73ba74dfaa520b49a401b5d21459a8523a146f3b7518a833eea5efa85130bf68': 'Apache-2.0',
    '17b5d209ba8f9684257ecfcff87df6ceda6194143a8fbd074f29727cff6f0c40': 'BSD-3-Clause',
    '8461c85d96b70f125b738d807b362b50d1014f16fd4ee549215eaa03d4a809a1': 'BSD-3-Clause',
    'd906c9396b6805d16bbaaa8844c58a44c46159bfe494443c1e4cfbc791103dcc': 'BSD-3-Clause',
    '0a8d61ed3cbfd5312326e8126c31ce9c627a283adc99131b56896d29ada04b2d': 'BSD-3-Clause',
    '2c6de2798f2ec318d5e6724e60895c91f852dd216747bd882990c053f913b311': 'MIT',
    'b95218cd9607855a6536384c0262922b30a0c2bf56e4ced790240f3a3bac4722': 'BSD-3-Clause',
    'a15b1d1b168954c92ff7fb1620382418f7c72f4f4d251ee791d1098ad68ab0c4': 'BSD-3-Clause',
    '20873bd48d04a4e4075ee881ec2a5f3a3b14bf4920018b1131a7c52ec9b4a318': 'BSD-3-Clause',
    '6d462371baa8649492b06f51f154dba9b25d2ac9548369b8b4fdbbbb85f2f75d': 'BSD-3-Clause',
    'b73277f7730993ef8e7f80aed83e5309762fed4d77eced982abb2c00657c074d': 'BSD-3-Clause',
    '08eab1118c80885fa1fa6a6dd7303f65a379fcb3733e063d20d1bbc2c76e6fa1': 'MIT',
    '9b44ae21e39b0ec20e89984bfb437d20617236285c051c42d95672babe2dad62': 'Apache-2.0',
    '7c87873291f289713ac5df48b1f2010eb6963752bbd6b530416ab99fc37914a8': 'Apache-2.0',
    '5a1094b566b6363140fd907ec10aa99f1a5b435c318fa1f65ed52a5e80c67029': 'MIT',
    'aa1376b9bc5dea6f30cdefde40c176a254f247d2814d0a9929395138631b2ae0': 'BSD-3-Clause',
    'aceb55133c41c50c2e170c5918e301fe74f592d0f28724bf2f7a7bfdcff1fc5f': 'Apache-2.0',
    'b0a3f39513927db306adabea11d14c23f079d4febcea241d123a68d1a0d45418': 'Apache-2.0',
    'a964a27c435167bdd78827ff83e4bd4473eca53d583a39598d2f445894a9225d': 'Apache-2.0',
    '79911c70a86bb521691b67fd09ada068beada62b478b82c9cc69d0b0dc3083d6': 'MIT',
    'd55cd95fdeb325687bd8e97a18d189c06032478215a9c5edc21b56d119c4b570': 'MIT',
    '26844e4b53c5adec04e557fd7dfef281cc0205a7d355626b1c68b778b99e9e7b': 'MIT',
    '4801bb0c5d70b980b3e1f63d1d2df8d84fec22548e3d73f03a68df1fb808791f': 'BSD-2-Clause',
    '8d427fd87bc9579ea368fde3d49f9ca22eac857f91a9dec7e3004bdfab7dee86': 'BSD-2-Clause',
    'c75aacd1e1f49bc504e3f00e7cfa58cb55d3bc7ff3d3c23f38e485da1906e0ad': 'Apache-2.0',
    '2eb550be6801c1ea434feba53bf6d12e7c71c90253e0a9de4a4f46cf88b56477': 'BSD-3-Clause',
    'c108a2604f8958f647b56b83b11a31ae85648a77cb9aa0f093c0ab9ffffe2222': 'BSD-3-Clause',
    'a3a7dff87da3927db65cb4c87b1cfbc96ca2755704461a485d457be7ae300a86': 'BSD-2-Clause',
    'f5d89b33f80e85421ff57c72306652ac3bd3b9c334c0c0be25884eb6173c6b6c': 'MIT',
    '332f612b58912b599da90b1f663886fb94761bea6d68832fa6197cd5b4944afd': 'MIT',
    '75e1ca97a84a9da6051dee0114333388216f2c4a5a028296b882ff3d57274735': 'BSD-2-Clause',
    'c4129f2c2a5eb20e4ac7b2535dab899fde485865106a15189726e2db68ff3483': 'MIT',
    'c8858a5a76440bbca484e134cf7df46385d090dd18b2c58e650f939258802e5b': 'Apache-2.0',
    'a8ad31b1c3f40dca5a84119351b8fa8ddc868edd77fad8a8ebf6d8f2d16fa4ae': 'Apache-2.0',
    '364a130d2ca340bd56eb1e6d045fc6929bb0f9d0aa018f2c1949b29517e1cdd0': 'Apache-2.0',
    'b8514c577c1c4b46cee454d5a882b15fa411e72c5bd7f801f241591789fce61a': 'BSD-3-Clause',
    'b2663894033a05fd80261176cd8da1d72546e25842d5c1abcc852ca23b6b61b0': 'MIT',
    '5d6687371c33901443a366627cf4025618f1ab99006ab494381ccae6e37bcbbe': 'Apache-2.0',
    '25ad56f47146a8c6e502d5b1eefe145933b460a8b314bbb66bb7fc964b92298b': 'MIT',
    '3f552a949c0023b9c833138f479bcc9632c7faa5c7bd3f54c6f8d345c7b5e3a3': 'Apache-2.0',
    '701cbcc144a7c865b072f27547e66ddbf17ac44a3bd21f71149ace02518f107c': 'BSD-3-Clause',
    'b7433de1a47cb43a83a1f5f6eb4317a4e119300af943bf1ce28ed271feb1efe2': 'BSD-3-Clause',
    '1530185dd39cdde7cb2f786a7a5fcf8bc34368b6ae73c15e72bafe88fd80b9a2': 'BSD-2-Clause',
    '0f02aac22084ef463aa5f42f566feeec6aa4c99653519744a8c25cb079da5b5d': 'BSD-2-Clause',
    'c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08': 'Apache-2.0',
    '745f8f53e61ad2f8463a27b77aac1636dc3a121ed8bd841e82397226fdcb4bae': 'Apache-2.0',
    '52323e7c7c14ed38010ab5879499eb2afd4abcce543750d0c3faf28d83c8d862': 'MIT',
    'a94710b55e03b5285f77d048c5ba61bb9d6ee04a06c0eb90e68821e11b0c707a': 'MIT',
    '4a4e095045f46875715234a884741acd2b61b88959d6f47a243ae03ef95c4e76': 'Apache-2.0',
    '911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad': 'BSD-3-Clause',
    'f9a2df4fb1d45cef691b8bc2e35776f8bee5af5b3696d48d4547635d7858bf91': 'BSD-3-Clause',
    '6a358d2540ca14048f02d366f23787c0a480157e58f058113f0e27168dd4e447': 'BSD-3-Clause',
    'f69f157b0be75da373605dbc8bbf142e8924ee82d8f44f11bcaf351335bf98cf': 'BSD-3-Clause',
    '08683b14bda8ae3538abf19e1879e853a39e3b8276a8d673363b529d15a61c1a': 'BSD-3-Clause',
    '406aaae58631f6ab5428b2890437db692d8403c4f80694cb5740bb897d199ffc': 'MIT',
    '4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20': 'BSD-3-Clause',
    '110244b02140866ee37d17fa7449436a377ec3b85a481fbb208f4c87964382de': 'BSD-3-Clause',
    'fc0a2f71df4e8f047902da53d1f85301be43e0f360fc167057a2d04658ed2ba9': 'BSD-3-Clause',
    'f6918bd93ffe07f4b2c61b8287c32cb3122e08aed0be50f1c7d0eddc87877a8f': 'Apache-2.0',
    '986175a94c6ab7f33be5d3b5018797147a6cc740c357597fdb1ca679b72206a8': 'BSD-2-Clause',
    '881467e52efeb1807406134b0ec04b1c6f52dc9dc49382713ef9ac4e0cae42f8': 'Apache-2.0',
    'bd773be0928aebf73959b15de6edd7abf4e78014bc9e8be3b96142ca251a018f': 'BSD-3-Clause',
    '32ae9a06ce10bb95444eaef5a0a6fe171c2b088a0ace3a03daaf5ff5dd60a8f7': 'BSD-3-Clause',
    '182a1bc8985a586e8e0ca3b5a3af1ff3c28bd3475833a07f50b42b53dd7ac889': 'BSD-3-Clause',
    '1033ec013241782ef9264400da6635b26b7a14674d9601c6c767be84ad778af4': 'BSD-3-Clause',
}
_ANCILLARY_FILES = {
    '3e0c7c091a948b82533ba98fd7cbb40432d6f1a9acbf85f5922d2f99a93ae6bb': (
        'license-declaration', 'Apache-2.0 OR BSD-3-Clause', (
            ('LICENSE.APACHE', 'aac73b3148f6d1d7111dbca32099f68d26c644c6813ae1e4f05f6579aa2663fe'),
            ('LICENSE.BSD', '602c4c7482de6479dd2e9793cda275e5e63d773dacd1eca689232ab7008fb4fb'))),
    '80e177ab397d5f332954693a52abc1b34b06c5792dd57297608b6d68a2f6af11': (
        'attribution', 'Apache-2.0', (
            ('LICENSE.txt', '0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594'),)),
    'd7390c793c73c36265497ffac90a886a235c8b50948454c9af98f1aef2a00d2a': (
        'attribution', 'MIT', (
            ('LICENSE', '835586ae156766a24e3c103fbc55d9af6b1a16df57ca932c97482a2737fd83d5'),)),
    'df58f69ea88683035d720b5375bcef0cf5aeaa98a1d098d572e0992c378deb46': (
        'attribution', 'Apache-2.0', (
            ('licenses/LICENSE_APACHE', 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4'),)),
}


# Each tuple identifies all complete grants in one retained whole-file body.
# IDs are deduplicated; the original file retains every attribution and grant.
_REVIEWED_BUNDLES = {
    'ec62dc96da0099b87f4511736c87309335527fb7031639493e06c95728dc8c54': ('MIT',),
    '11f2aafb37d06b3ee5bdaf06e9811141d0da05263c316f3d627f45c20d43261b': ('MIT',),
    '12b06934bd437fee7b52583c0b1062181957363f4f520dd7a5305362f3c9e6e6': ('ISC', 'MIT'),
    '871b440e9b348d6b2485c72e15f1d18f4cf8ee7bb424cbcd854b6a4a772b61d8': ('BSD-2-Clause', 'ISC'),
    'a15a6f732df3a033a71853ce1d255bd671f00fbc537fa629b78d71baecda0ace': ('MIT',),
    'b92ba0f6ee02f2309628bfdadb123668a17c016e475ba477b857d33470d9d625': ('MIT',),
    '1ae07514be1d7bb33f0698f8d91fb51b8b9fe1463157ec1c72081a49b9bc6f40': ('Apache-2.0', 'BSD-3-Clause'),
    'b0da1764fe4d13d610b695536fc3f2ebc362482d053a1cd258e36975bc6b97a7': ('BSD-3-Clause',),
    '0d9e582ee4bff57bf1189c9e514e6da7ce277f9cd3bc2d488b22fbb39a6d87cf': ('BSD-3-Clause', 'Apache-2.0', 'MIT'),
}


def recognized_license_bundle(text: str) -> tuple[str, ...] | None:
    """Identify an exact reviewed multi-grant file, never infer an SPDX branch.

    Return every distinct existing license ID present in the complete file.
    The caller must retain all original bytes and separately check its SPDX
    expression and policy. Unknown or altered containers return None.
    Single-license files use recognized_license; that API remains unchanged.
    """
    return _REVIEWED_BUNDLES.get(hashlib.sha256(text.encode('utf-8')).hexdigest())


def reviewed_ancillary(text: str) -> dict | None:
    """Return exact-file retention requirements, never complete license credit.

    Resolve required_files relative to this file's parent. The consumer must
    match the current expression and verify each exact sibling's complete terms.
    """
    value = _ANCILLARY_FILES.get(hashlib.sha256(text.encode('utf-8')).hexdigest())
    if value is None:
        return None
    kind, expression, required = value
    return {'kind': kind, 'expression': expression, 'required_files': dict(required)}


def recognized_license(text: str) -> str | None:
    """Return one qualified standard ID, or None for unknown/incomplete terms."""
    exact = _REVIEWED_FILES.get(hashlib.sha256(text.encode('utf-8')).hexdigest())
    if exact is not None:
        return exact
    lines = [line.strip() for line in text.splitlines()
             if re.fullmatch(r'\s*SPDX-License-Identifier:\s*[A-Za-z0-9][A-Za-z0-9.+:\- ()]*\s*', line) is None]
    copyrighted = False
    while lines:
        first = lines[0]
        if not first or first.casefold() in _TITLES or first.casefold() == 'all rights reserved.':
            lines.pop(0)
        elif re.fullmatch(r'(?i)copyright\s+(?:\(c\)\s*|©\s*)?[0-9]{4}(?:[0-9 ,\-]*[0-9])?,?\s+[^<>\n]{1,240}', first):
            # Copyright attribution is retained verbatim in the evidence hash.
            # A sentence introducing additional rights is not an owner field.
            if re.search(r'(?i)\b(?:license|permission|redistribution|prohibited|restriction|except)\b', first):
                return None
            copyrighted = True
            lines.pop(0)
        else:
            break
    body = re.sub(r'(?m)^\s*(?:[1-3]\.|[*-])\s+(?=(?:Redistributions|Neither)\b)', '', '\n'.join(lines))
    digest = hashlib.sha256(' '.join(body.split()).casefold().encode()).hexdigest()
    identifier = _TERMS.get(digest)
    if identifier in {'MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'} and not copyrighted:
        return None
    return identifier
