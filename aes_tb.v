`timescale 1ns / 1ps

module AES_tb;

    // ----------------------
    // AES Inputs & Outputs
    // ----------------------
    reg  [127:0] plaintext;
    wire [127:0] ciphertext;
    reg  [127:0] decrypt_key;
    wire [127:0] decrypted;

    // Single correct master key for encryption
    localparam [127:0] master_key = 128'h000102030405060708090a0b0c0d0e0f;

    // ----------------------
    // Memory Interface
    // ----------------------
    reg         clk;
    reg         we;
    reg  [11:0] addr;
    reg  [7:0]  din;
    wire [7:0]  dout;

    // ----------------------
    // Access Control
    // ----------------------
    wire access_granted;

    // ----------------------
    // Module Instantiations
    // ----------------------
    AES_Encrypt encrypt_inst (
        .in (plaintext),
        .key(master_key),
        .out(ciphertext)
    );

    AES_Decrypt decrypt_inst (
        .in (ciphertext),
        .key(decrypt_key),
        .out(decrypted)
    );

    secure_memory_access mem_ctrl (
        .clk          (clk),
        .we           (we),
        .addr         (addr),
        .din          (din),
        .access_granted(access_granted),
        .dout         (dout)
    );

    // Grant access when decryption recovers the original plaintext
    assign access_granted = (decrypted == plaintext);

    // ----------------------
    // Clock Generation
    // ----------------------
    initial clk = 0;
    always #5 clk = ~clk;

    // ----------------------
    // Test Vectors
    // ----------------------
    reg [127:0] pt [0:3];
    reg [127:0] key_vec [0:3];
    reg         expected_grant [0:3];
    integer i;

    initial begin
        $dumpfile("aes_testbench.vcd");
        $dumpvars(0, AES_tb);

        $display("=========== AES-128 Secure Boot + Memory Access Test ===========");

        // Prepare 4 cases: only first two use the correct decryption key
        pt[0]        = 128'h00112233445566778899aabbccddeeff;
        key_vec[0]   = master_key;  expected_grant[0] = 1;

        pt[1]        = 128'h1234567890abcdef1234567890abcdef;
        key_vec[1]   = master_key;  expected_grant[1] = 1;

        pt[2]        = 128'haaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        key_vec[2]   = 128'hffffffffffffffffffffffffffffffff;  expected_grant[2] = 0;

        pt[3]        = 128'hcafebabecafebabecafebabecafebabe;
        key_vec[3]   = 128'h11111111111111111111111111111111;  expected_grant[3] = 0;

        // Loop through each test case
        for (i = 0; i < 4; i = i + 1) begin
            $display("\n----------- Test Case %0d -----------", i);

            // Set plaintext and decryption key
            plaintext   = pt[i];
            decrypt_key = key_vec[i];

            #20;  // Wait for AES modules

            // Display AES results
            $display("PLAINTEXT        = %h", plaintext);
            $display("MASTER KEY       = %h", master_key);
            $display("CIPHERTEXT       = %h", ciphertext);
            $display("DECRYPTION KEY   = %h", decrypt_key);
            $display("DECRYPTED OUTPUT = %h", decrypted);
            $display("ACCESS GRANTED?  = %b (expected %b)", access_granted, expected_grant[i]);

            // Try a memory write
            addr = 12'h040 + i;
            din  = i + 8'hA0;
            we   = 1;
            $display("Trying to write 0x%h to memory address 0x%h", din, addr);
            #10 we = 0; #10;

            // If access granted, verify a second write/read
            if (access_granted) begin
                $display("Access granted, performing secured memory transaction...");
                addr = 12'h080 + i;
                din  = i + 8'hF0;
                $display("Writing 0x%h to memory address 0x%h", din, addr);
                we   = 1;
                #10 we = 0; #10;
                $display("Read back from 0x%h => 0x%h", addr, dout);
            end else begin
                $display("Access denied, memory operation blocked.");
            end
        end

        $display("\n=========== All Test Cases Completed ===========");
        $finish;
    end

endmodule

