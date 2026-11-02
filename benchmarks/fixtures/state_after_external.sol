contract StateAfterExternal {
    uint256 public stored;

    function pull(address target, bytes calldata data) external {
        target.call(data);
        stored = 1;
    }
}
