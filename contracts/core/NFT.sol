// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../libs/access/AccessControl.sol";
import "../libs/token/ERC721/extensions/ERC721URIStorage.sol";
import "../libs/utils/cryptography/ECDSA.sol";
import "../libs/utils/Strings.sol";

contract ERC721MintWithSig is ERC721URIStorage, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    uint256 public upperLimit;
    uint256 public lowerLimit;

    constructor(string memory name, string memory symbol, uint256 _lowerLimit, uint256 _upperLimit)
    ERC721(name, symbol)
    {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        upperLimit = _upperLimit;
        lowerLimit = _lowerLimit;
    }

    modifier withinRange(uint256 tokenId) {
        require(
            tokenId>=lowerLimit && tokenId<=upperLimit, 
            string(
                abi.encodePacked(
                    "Invalid token id, only between ",Strings.toString(lowerLimit)," and ",Strings.toString(upperLimit)," is permitted")));
        _;
    }

    function setClaimRange(uint256 _lowerLimit, uint256 _upperLimit) onlyRole(DEFAULT_ADMIN_ROLE) external {
        upperLimit = _upperLimit;
        lowerLimit = _lowerLimit;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function claim(address account, uint256 tokenId, string memory uri, bytes calldata signature)
    external withinRange(tokenId)
    {
        require(_verify(_hash(account, tokenId, uri), signature), "Invalid signature");
        _safeMint(account, tokenId);
        _setTokenURI(tokenId, uri);
    }

    function _hash(address account, uint256 tokenId, string memory uri)
    internal pure returns (bytes32)
    {
        return ECDSA.toEthSignedMessageHash(keccak256(abi.encodePacked(tokenId, account, uri)));
    }

    function _verify(bytes32 digest, bytes memory signature)
    internal view returns (bool)
    {
        return hasRole(MINTER_ROLE, ECDSA.recover(digest, signature));
    }

    function mintWithURI(address to, uint256 tokenId, string memory uri) onlyRole(MINTER_ROLE) external {
        require(!_exists(tokenId), "token id already exist");
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }
}