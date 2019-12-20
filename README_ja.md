# OpenAM (OpenAM コンソーシアム版)

OpenAM は認証、認可、エンタイトルメント、およびフェデレーション機能を提供する「オールインワン」アクセス管理ソリューションです。

## ドキュメント

このプロジェクトは [GitHub wiki ページ][github_wiki]でドキュメントを提供します。

## OpenAM アプリケーションの取得

OpenAM WAR ファイルは [GitHub releases ページ][github_releases]から入手できます。

利用する前には[ライセンス](#ライセンス)をお読みください。

## ソースコードからのビルド

### 前提条件

ソフトウェア           | 必要なバージョン
---------------------- | ----------------
OpenJDK                | 1.8 以上
Maven                  | 3.1.0 以上
Git                    | 1.7.6 以上

### ビルド

OpenAM のビルドプロセスと依存関係は、Maven で管理されています。

現時点では、OpenAMおよび関連製品はMavenリポジトリに登録されていないため、Maven ローカルリポジトリができるまではすべてのプロジェクトをビルドする必要があります。

以下のプロジェクトをクローンし、`mvn clean install` を順番に実行してください。

なお、コマンドは 非 root ユーザーで実行してください。

* [forgerock-parent](https://github.com/openam-jp/forgerock-parent)
* [forgerock-bom](https://github.com/openam-jp/forgerock-bom)
* [forgerock-build-tools](https://github.com/openam-jp/forgerock-build-tools)
* [forgerock-i18n-framework](https://github.com/openam-jp/forgerock-i18n-framework)
* [forgerock-guice](https://github.com/openam-jp/forgerock-guice)
* [forgerock-ui](https://github.com/openam-jp/forgerock-ui)
* [forgerock-guava](https://github.com/openam-jp/forgerock-guava)
* [forgerock-commons](https://github.com/openam-jp/forgerock-commons)
* [forgerock-persistit](https://github.com/openam-jp/forgerock-persistit)
* [forgerock-bloomfilter](https://github.com/openam-jp/forgerock-bloomfilter)
* [opendj-sdk](https://github.com/openam-jp/opendj-sdk)
* [opendj](https://github.com/openam-jp/opendj)
* [openam](https://github.com/openam-jp/openam)

最後に、`openam/openam-server/target` にバイナリが作成されます。ファイル名の形式は `OpenAM-<バージョン>.war` です。


### OpenJDK11 環境で動作させるための追加手順

OpenJDK11 環境で OpenAM を使用する場合は、追加の手順を実施して下さい。

1. OpenAMのビルドを完了し、`OpenAM-<バージョン>-SNAPSHOT.war` を取得します。

2. 以下のプロジェクトをクローンし、`mvn clean install` を実行してください。 

<li><a href="https://github.com/openam-jp/jdk8-compat">jdk8-compat</a></li>

   コマンドの実行後、`jdk8-compat/target` にバイナリが作成されます。ファイル名の形式は、`jdk8-compat-<バージョン>.jar` です。

3. 以下のフォルダ構成になるようにOpenAMとjdk8-compatのバイナリファイルを配置します。

       ./OpenAM-<バージョン>-SNAPSHOT.war
       ./WEB-INF/lib/jdk8-compat-<バージョン>.jar


4. `OpenAM-<バージョン>-SNAPSHOT.war` に `jdk8-compat-<バージョン>.jar` を追加します。

       jar uf OpenAM-<バージョン>-SNAPSHOT.war WEB-INF/lib/jdk8-compat-<バージョン>.jar

5. 以上で OpenJDK11 環境への対応は完了となります。


## コントリビューション

このプロジェクトはあなたのコントリビューションを歓迎します。

バグを見つけたり、改善のアイデアをお持ちの場合は、最初のステップとして [Issue][github_issues] をオープンしてください。
ただし、セキュリティ上の問題が含まれている場合は、Issue をオープンせずに[メールでご連絡ください][mail_openam_dev]。

## ライセンス

このプロジェクトは、[Common Development and Distribution License（CDDL）](LICENSE.md)が適用されます。

利用する前に、CDDL ライセンスの全ての条項を確認ください。

特に下記の「5. DISCLAIMER OF WARRANTY（保証の免責）」にご留意ください。

```
5. DISCLAIMER OF WARRANTY（保証の免責）
対象ソフトウェアは本ライセンスに基づき「現状のまま」提供されるものとし、
明示黙示を問わず、欠陥がないとの保証や、商業的な使用可能性、特定の目的に
対する適合性、非侵害性などの保証を含め、いかなる保証もありません。
対象ソフトウェアの品質および性能に関するリスクはすべて使用者が負うものと
します。
```

[Open Source Group Japan 日本語参考訳からの引用](https://osdn.net/projects/opensource/wiki/licenses%2FCommon_Development_and_Distribution_License)

## 謝辞

* Sun Microsystems.
* ForgeRock.
* The good things in life.

## 他言語版

* [English](README.md)

[mail_openam_dev]: mailto:openam-dev@OpenAM.jp
[github_issues]: https://github.com/openam-jp/openam/issues
[github_wiki]: https://github.com/openam-jp/openam/wiki
[github_releases]: https://github.com/openam-jp/openam/releases

