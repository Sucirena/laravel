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
        Schema::create('diskusi', function (Blueprint $table) {
            $table->uuid('id')->primary(); // Primary key, ID unik untuk setiap diskusi
            $table->unsignedBigInteger('id_pasien')->nullable(); // Foreign key merujuk pada tabel pasien
            $table->string('judul', 50); // Judul diskusi
            $table->longText('isi'); // Isi dari diskusi
            $table->timestamps(); // Kolom created_at dan updated_at

            // Definisi foreign key
            $table->foreign('id_pasien')->references('id')->on('pasien')->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('diskusi');
    }
};
