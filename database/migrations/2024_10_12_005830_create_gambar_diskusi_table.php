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
        Schema::create('gambar_diskusi', function (Blueprint $table) {
            $table->id(); // Primary key, ID unik untuk setiap gambar diskusi
            $table->uuid('id_diskusi'); // Foreign key merujuk pada tabel diskusi
            $table->string('gambar', 255); // Nama file gambar yang diunggah dalam diskusi

            // Definisi foreign key
            $table->foreign('id_diskusi')->references('id')->on('diskusi')->onDelete('cascade');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('gambar_diskusi');
    }
};
