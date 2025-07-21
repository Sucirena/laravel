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
        Schema::create('pesan_chatbot', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap pesan chatbot
            $table->uuid('id_percakapan_chatbot'); // Foreign key merujuk pada tabel percakapan_chatbot
            $table->longText('teks'); // Isi teks dari pesan
            $table->enum('pengirim', ['bot', 'pengguna']); // Pengirim pesan (bot atau pengguna)
            $table->timestamps(); // Kolom created_at dan updated_at

            // Definisi foreign key
            $table->foreign('id_percakapan_chatbot')->references('id')->on('percakapan_chatbot')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('pesan_chatbot');
    }
};
