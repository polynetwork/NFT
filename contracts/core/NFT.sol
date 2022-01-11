// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../libs/access/AccessControl.sol";
import "../libs/token/ERC721/extensions/ERC721URIStorage.sol";
import "../libs/token/ERC721/extensions/ERC721Enumerable.sol";
import "../libs/utils/cryptography/ECDSA.sol";
import "../libs/utils/Strings.sol";

contract ERC721MintWithSig is ERC721Enumerable, AccessControl {
    using Strings for uint256;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    uint256 public upperLimit;
    uint256 public lowerLimit;
    uint256 public deadline;

    // Optional mapping for token URIs
    mapping (uint256 => string) private _tokenURIs;

    constructor(string memory name, string memory symbol, uint256 _lowerLimit, uint256 _upperLimit, uint256 _deadline)
    ERC721(name, symbol)
    {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        upperLimit = _upperLimit;
        lowerLimit = _lowerLimit;
        deadline = _deadline;
    }

    modifier withinRange(uint256 tokenId) {
        require(
            tokenId>=lowerLimit && tokenId<=upperLimit, 
            string(
                abi.encodePacked(
                    "Invalid token id, only between ",Strings.toString(lowerLimit)," and ",Strings.toString(upperLimit)," is permitted")));
        _;
    }

    modifier withinDeadline() {
        require(deadline == 0 || block.timestamp <= deadline, "Claim entrance is closed!");
        _;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721URIStorage: URI query for nonexistent token");

        string memory _tokenURI = _tokenURIs[tokenId];
        string memory base = _baseURI();

        // If there is no base URI, return the token URI.
        if (bytes(base).length == 0) {
            return _tokenURI;
        }
        // If both are set, concatenate the baseURI and tokenURI (via abi.encodePacked).
        if (bytes(_tokenURI).length > 0) {
            return string(abi.encodePacked(base, _tokenURI));
        }

        return super.tokenURI(tokenId);
    }

    function setClaimRange(uint256 _lowerLimit, uint256 _upperLimit) onlyRole(DEFAULT_ADMIN_ROLE) external {
        upperLimit = _upperLimit;
        lowerLimit = _lowerLimit;
    }

    function setDeadline(uint256 _deadline) onlyRole(DEFAULT_ADMIN_ROLE) external {
        deadline = _deadline;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControl, ERC721Enumerable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function claim(address account, uint256 tokenId, string memory uri, bytes calldata signature)
    external withinDeadline withinRange(tokenId) 
    {
        require(_verify(_hash(account, tokenId, uri), signature), "Invalid signature");
        _safeMint(account, tokenId);
        _setTokenURI(tokenId, uri);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal virtual {
        require(_exists(tokenId), "ERC721URIStorage: URI set of nonexistent token");
        _tokenURIs[tokenId] = _tokenURI;
    }

    /**
     * @dev Destroys `tokenId`.
     * The approval is cleared when the token is burned.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     *
     * Emits a {Transfer} event.
     */
    function _burn(uint256 tokenId) internal virtual override {
        super._burn(tokenId);

        if (bytes(_tokenURIs[tokenId]).length != 0) {
            delete _tokenURIs[tokenId];
        }
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