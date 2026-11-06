// SPDX-License-Identifier: BUSL-1.1
// Copyright: OKcontract Pte. Ltd.
pragma solidity ^0.8.36;

// Pause policy table corresponding to doc/registry-containment.json.
// Unknown selectors fail closed during pause, including newly installed facets.
library RegistryContainmentSelectors {
    bytes private constant ALLOWED =
        hex"01e8652c0101ffc9a7010275e2630102fff9db0103d59e120104e4ffb10104ffd4ca0106545a930108615d080109cbea41010a045359010b4532ec010c57097b010c6cdf21010cb2a577010d78a264010f8380bf0110ddd8dc01143fab290115a098e2011813462b01184ad72b01185f7a8101193fadc6011aa770b4011b7cda7f011e4c603b011fa8eeed011fd9a8c601200228ad01210a57b801214b92fb0123d2625301248a9ca3012561f1b001275cdad50127d1931301291e1665012c182015012d0743ba012e2804d1012e9a82dc012f211945013423d8070135828dd70135ac9e280136568abe02379ba0ca0138a8643d013bb77715013bda8b28013f4ba83a013ff06346014100f7a20141b46223014209fff101425ca3d30144afbee3014a38ee9f014c8e01190150ea07970250f37c8b0151bad0aa01525bcdb6015286cb830152d1902d0152ef6b2c01564fa65601567ab96c0156a053fb01582d6cda0158fe673d01599faa2a015c975abb015d85958d015dccfc100162fc50af0164771cf20164c8158a01658f06500165d5548f016733f2f00167a8b2f30167da07cd016933a44c01696f541c0169bd571c016b2b7dd8016c052cd8016c6dc03d016c91fcbd01703c376e0170dba0a30170ecdc6501715018a60272ef77520173b1253c01758a75490175b238fc01781a196701781cc3d30278a895670178b7a92301790bf12901791b6d6001795a4172017a0ed627017a0f2317017aba5dc9017b35c9c4017c1a2272017c29fae6017f5eb9f6017ff971e80180001d89018044a2d501806c463a01813d25820181bd1f9601823f549b018341635d018410a4a3018456cb590186fd8385018a3ca0b0018c51a31b018d22ea2a018da5cb5b018e35d39d018fa626fd0190f81e5b0191d14854019278a8c5019399869d019404a2040194dbb85a019538d2ff019669893b01971023930199a2eda0019ac6897f019b136bd2019b4735c9019b771bf7019bea7148019d8d8900019ed8e1f001a03632e701a0a721a701a1840e6902a217fddf01a3f685f901a6a06dc301a6b1b53e01a6c3c57d01a6d9531701a731e2f401a92d1fc601a94f681a01a98e4e7701aa7cedaf01aabf5e5501aac6443201ac9650d801acda16fd01ad3cb1cc01ade51eba01adfca15e01ae8009d601aea0e5a101aee39cbb01af74f0eb01afe5eefa01b0d7c57d01b2f785c101b53be0b801b5882b4d01b5cb15f701b63e118501b7d58b1301ba2ae38401ba3f5ddf01ba46658601ba4e520b01bb1bd6e801be41be9601bf293cfc01bf61213d01c1c1245801c4467a4a01c5819fcc01c582485c01c668b71001c68f2ada01c6bc259401c6dde13a01c6e064ad01c76eb50c01c799ece501c7a0ea3301c7eaaf8601c865562d01c872595901cbdf309a01cc29d21702cc6e795a01ccdbf1d601cd5685d601cdffacc601ce5539d201d103538801d22052ac01d2449d0201d30b54c701d3c7420501d489e4a901d5969eaa01d7f4e94601d8724ae102d8e517d101da7d237201dc5699d202dca22dcd01dce9f07001ddc2079f01df84bc9901df9517ff01e202cf4801e293bf6c01e30c397801e3a31fa801e4ce5cc301e50e4efa02e54c373101e59771d201e65a331c01e7d8c44d01e7d953ff01e836f31801eb8fe31201ef0da76601f157c0ac01f2593d7d01f27c07b301f367fadb01f728918a01f72c0d8b01f7c0ada901f9758a1c01f9de538501fa7428de01faf5d86601fce95e7a01fd7338fb01fee2f12901ff9de31701ffa1ad7401";

    function allowed(bytes4 selector) internal pure returns (bool) {
        return policy(selector) != 0;
    }

    // 0 rejects; nonzero permits an independently authorized call.
    function policy(bytes4 selector) internal pure returns (uint8) {
        bytes memory packed = ALLOWED;
        uint256 low = 0;
        uint256 high = packed.length / 5;
        while (low < high) {
            uint256 middle = (low + high) / 2;
            bytes4 candidate;
            assembly ("memory-safe") {
                // The integer midpoint selects a five-byte record; this multiplication is byte indexing.
                // forge-lint: disable-next-line(divide-before-multiply)
                candidate := mload(add(add(packed, 0x20), mul(middle, 5)))
            }
            // Read the policy byte of that same five-byte record; midpoint rounding is intentional.
            // forge-lint: disable-next-line(divide-before-multiply)
            if (candidate == selector) return uint8(packed[middle * 5 + 4]);
            if (candidate < selector) low = middle + 1;
            else high = middle;
        }
        return 0;
    }
}
