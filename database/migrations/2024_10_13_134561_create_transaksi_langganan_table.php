<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('transaksi_langganan', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap transaksi
            $table->unsignedBigInteger('id_user')->nullable(); // Relasi ke tabel users
            $table->string('snap_token')->unique(); // ID transaksi unik dari Midtrans
            $table->decimal('amount', 10, 2); // Jumlah pembayaran
            $table->string('payment_method')->nullable(); // Metode pembayaran (bisa kosong jika masih pending)
            $table->enum('status', ['pending', 'canceled', 'expired', 'paid'])->default('pending'); // Default status saat transaksi dibuat
            $table->timestamp('expired_at')->nullable();
            $table->timestamps(); // Timestamps created_at dan updated_at
        
            // Foreign key
            $table->foreign('id_user')->references('id')->on('user')->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('transaksi_langganan');
    }
};
