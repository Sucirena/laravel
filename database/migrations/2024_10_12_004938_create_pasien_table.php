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
        Schema::create('pasien', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap pasien
            $table->unsignedBigInteger('id_user'); // Foreign key merujuk pada tabel User
            $table->text('deskripsi_diri')->nullable(); // Deskripsi diri pasien

            // Definisi foreign key
            $table->foreign('id_user')->references('id')->on('user')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('pasien');
    }
};
