// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.23;

import "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import "@openzeppelin/contracts/utils/Strings.sol";


import {ScaleCodec} from "../src/utils/ScaleCodec.sol";

contract ScaleCodecTest is Test {
    function testEncodeU256() public {
        assertEq(
            ScaleCodec.encodeU256(12063978950259949786323707366460749298097791896371638493358994162204017315152),
            hex"504d8a21dd3868465c8c9f2898b7f014036935fa9a1488629b109d3d59f8ab1a"
        );
    }

    function testEncodeU128() public {
        assertEq(ScaleCodec.encodeU128(35452847761173902980759433963665451267), hex"036935fa9a1488629b109d3d59f8ab1a");
    }

    function testEncodeU64() public {
        assertEq(ScaleCodec.encodeU64(1921902728173129883), hex"9b109d3d59f8ab1a");
    }

    function testEncodeU32() public {
        assertEq(ScaleCodec.encodeU32(447477849), hex"59f8ab1a");
    }

    function testEncodeU16() public {
        assertEq(ScaleCodec.encodeU16(6827), hex"ab1a");
    }

    function testEncodeCompactU32() public {
        assertEq(ScaleCodec.encodeCompactU32(0), hex"00");
        assertEq(ScaleCodec.encodeCompactU32(63), hex"fc");
        assertEq(ScaleCodec.encodeCompactU32(64), hex"0101");
        assertEq(ScaleCodec.encodeCompactU32(16383), hex"fdff");
        assertEq(ScaleCodec.encodeCompactU32(16384), hex"02000100");
        assertEq(ScaleCodec.encodeCompactU32(1073741823), hex"feffffff");
        assertEq(ScaleCodec.encodeCompactU32(1073741824), hex"0300000040");
        assertEq(ScaleCodec.encodeCompactU32(type(uint32).max), hex"03ffffffff");
    }

    function testCheckedEncodeCompactU32() public {
        assertEq(ScaleCodec.checkedEncodeCompactU32(type(uint32).max), hex"03ffffffff");

        vm.expectRevert(ScaleCodec.UnsupportedCompactEncoding.selector);
        ScaleCodec.checkedEncodeCompactU32(uint256(type(uint32).max) + 1);
    }

    function testfuzz_CheckedEncodedCompactU32(uint256 value) public {
        vm.assume(value > type(uint32).max);

        vm.expectRevert(ScaleCodec.UnsupportedCompactEncoding.selector);
        ScaleCodec.checkedEncodeCompactU32(value);
    }

    //function testfuzz_EncodedCompactU32(uint32 value) public {
    //    vm.assume(value < type(uint32).max);

    //    assertEq(ScaleCodec.encodeCompactU32(value), hex"00");
    //}

    function bytesToString(bytes memory byteCode) public pure returns(string memory stringData)
{
    uint256 blank = 0; //blank 32 byte value
    uint256 length = byteCode.length;

    uint cycles = byteCode.length / 0x20;
    uint requiredAlloc = length;

    if (length % 0x20 > 0) //optimise copying the final part of the bytes - to avoid looping with single byte writes
    {
        cycles++;
        requiredAlloc += 0x20; //expand memory to allow end blank, so we don't smack the next stack entry
    }

    stringData = new string(requiredAlloc);

    //copy data in 32 byte blocks
    assembly {
        let cycle := 0

        for
        {
            let mc := add(stringData, 0x20) //pointer into bytes we're writing to
            let cc := add(byteCode, 0x20)   //pointer to where we're reading from
        } lt(cycle, cycles) {
            mc := add(mc, 0x20)
            cc := add(cc, 0x20)
            cycle := add(cycle, 0x01)
        } {
            mstore(mc, mload(cc))
        }
    }

    //finally blank final bytes and shrink size (part of the optimisation to avoid looping adding blank bytes1)
    if (length % 0x20 > 0)
    {
        uint offsetStart = 0x20 + length;
        assembly
        {
            let mc := add(stringData, offsetStart)
            mstore(mc, mload(add(blank, 0x20)))
            //now shrink the memory back so the returned object is the correct size
            mstore(stringData, length)
        }
    }
}

    function toHexDigit(uint8 d) internal pure returns (bytes1) {
        if (0 <= d && d <= 9) {
            return bytes1(uint8(bytes1("0")) + d);
        } else if (10 <= uint8(d) && uint8(d) <= 15) {
            return bytes1(uint8(bytes1("a")) + d - 10);
        }
        revert();
    }

    function fromCode(bytes4 code) public pure returns (string memory) {
        bytes memory result = new bytes(10);
        result[0] = bytes1("0");
        result[1] = bytes1("x");
        for (uint i = 0; i < 4; ++i) {
            result[2 * i + 2] = toHexDigit(uint8(code[i]) / 16);
            result[2 * i + 3] = toHexDigit(uint8(code[i]) % 16);
        }
        return string(result);
    }

    function fromBytes(bytes memory code) public pure returns (string memory) {
        uint256 len = code.length;
        bytes memory result = new bytes(2*len+2);
        result[0] = bytes1("0");
        result[1] = bytes1("x");
        for (uint i = 0; i < len; ++i) {
            result[2 * i + 2] = toHexDigit(uint8(code[i]) / 16);
            result[2 * i + 3] = toHexDigit(uint8(code[i]) % 16);
        }
        return string(result);
    }

    /// forge-config: default.fuzz.runs = 10
    function testEncodeU32Fuzzed(uint32 value) public {
        vm.assume(value < type(uint32).max);
        string[] memory rustInputs = new string[](6);

        rustInputs[0] = 'cargo';
        rustInputs[1] = 'run';
        rustInputs[2] = '--quiet';
        rustInputs[3] = '--manifest-path';
        rustInputs[4] = '../../differential_testing_scale/U32/Cargo.toml';
        rustInputs[5] = Strings.toString(value);

        bytes4 rustResults = bytes4(vm.ffi(rustInputs));

        vm.writeLine("./test/data/Output.txt", Strings.toString(value));
        string memory rust_encoded_in_hex = fromCode(rustResults);
        //vm.writeLine("./test/data/Output.txt", rust_encoded_in_hex);

        bytes4 solidityEncoded = ScaleCodec.encodeU32(value);
        string memory solidity_encoded_in_hex = fromCode(solidityEncoded);
        //vm.writeLine("./test/data/Output.txt", solidity_encoded_in_hex);
        assertEq(rust_encoded_in_hex, solidity_encoded_in_hex);

        //vm.writeLine("./test/data/Output.txt", fromCode(rustResults));
        //bytes32 rustEncoded = abi.decode(rustResults, (bytes4));
        //vm.writeLine("./test/data/Output.txt", bytesToString(abi.encode(rustResults)));        
    }

    /// forge-config: default.fuzz.runs = 1000
    function testEncodeCompactU32Fuzzed(uint32 value) public {

        vm.assume(value < type(uint32).max);
        string[] memory rustInputs = new string[](6);
        rustInputs[0] = 'cargo';
        rustInputs[1] = 'run';
        rustInputs[2] = '--quiet';
        rustInputs[3] = '--manifest-path';
        rustInputs[4] = '../../differential_testing_scale/compactU32/Cargo.toml';
        rustInputs[5] = Strings.toString(value);

        bytes memory rustResults = vm.ffi(rustInputs);
        vm.writeLine("./test/data/Output-CompactU32.txt", Strings.toString(value));
        string memory rust_encoded_in_hex = fromBytes(rustResults);
        vm.writeLine("./test/data/Output-CompactU32.txt", rust_encoded_in_hex);

        bytes memory solidityEncoded = ScaleCodec.encodeCompactU32(value);
        string memory solidity_encoded_in_hex = fromBytes(solidityEncoded);
        vm.writeLine("./test/data/Output-CompactU32.txt", solidity_encoded_in_hex);
        assertEq(rustResults, solidityEncoded);
    }
}