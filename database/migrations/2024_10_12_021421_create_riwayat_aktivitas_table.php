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
        Schema::create('riwayat_aktivitas', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap riwayat aktivitas
            $table->unsignedBigInteger('id_pasien'); // Foreign key untuk merujuk ke pasien terkait
            $table->unsignedBigInteger('id_aktivitas_positif'); // Foreign key untuk merujuk ke aktivitas positif yang dilakukan pasien
            $table->timestamps(); // Menambahkan kolom created_at dan updated_at

            // Menambahkan foreign key constraint untuk id_pasien
            $table->foreign('id_pasien')->references('id')->on('pasien')->onDelete('cascade');

            // Menambahkan foreign key constraint untuk id_aktivitas_positif
            $table->foreign('id_aktivitas_positif')->references('id')->on('aktivitas_positif')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('riwayat_aktivitas');
    }
};
