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
        Schema::create('jurnal_harian', function (Blueprint $table) {
            $table->uuid('id')->primary(); // Primary key, ID unik untuk setiap jurnal harian
            $table->unsignedBigInteger('id_pasien'); // Foreign key merujuk pada tabel Pasien
            $table->string('judul', 50)->nullable(); // Judul jurnal harian
            $table->longText('isi')->nullable(); // Isi dari jurnal harian
            $table->longText('nilai_emosi')->nullable(); // Nilai atau skor emosi yang dirasakan pasien
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
        Schema::dropIfExists('jurnal_harian');
    }
};
