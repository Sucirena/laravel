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
        Schema::create('kata_kunci_konten', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap kata kunci konten
            $table->unsignedBigInteger('id_konten'); // Foreign key untuk merujuk ke konten edukatif terkait
            $table->string('nama', 50); // Nama dari kata kunci konten

            // Menambahkan foreign key constraint untuk id_konten
            $table->foreign('id_konten')->references('id')->on('konten_edukatif')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('kata_kunci_konten');
    }
};
