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
        Schema::create('percakapan_chatbot', function (Blueprint $table) {
            $table->uuid('id')->primary(); // UUID sebagai primary key
            $table->unsignedBigInteger('id_pasien'); // Foreign key merujuk pada tabel Pasien
            $table->string('label', 255); // Label percakapan
            $table->dateTime('last_activity'); // Tanggal dan waktu aktivitas terakhir
            $table->enum('status', ['aktif', 'selesai']); // Status percakapan (aktif, selesai)
            $table->timestamps(); // Kolom created_at dan updated_at

            // Definisi foreign key
            $table->foreign('id_pasien')->references('id')->on('pasien')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('percakapan_chatbot');
    }
};
