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
        Schema::create('chatbot_log', function (Blueprint $table) {
            $table->id(); // ID log
            $table->unsignedBigInteger('id_pasien')->nullable(); // ID pengguna yang mengirim pesan
            $table->timestamp('sent_at'); // Waktu log dibuat
        
            // Foreign key untuk ID user
            $table->foreign('id_pasien')->references('id')->on('pasien')->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('chatbot_log');
    }
};
